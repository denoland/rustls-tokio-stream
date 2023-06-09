use rustls::Connection;
use std::io;
use std::io::ErrorKind;

use tokio::net::TcpStream;

use crate::adapter::read_tls;
use crate::adapter::write_tls;
use crate::TestOptions;

async fn try_read<'a, 'b>(
  tcp: &'a mut TcpStream,
  tls: &'b mut Connection,
) -> io::Result<()> {
  match read_tls(tcp, tls) {
    Ok(n) if n == 0 => {
      // EOF during handshake
      return Err(ErrorKind::UnexpectedEof.into());
    }
    Ok(_) => {
      tls
        .process_new_packets()
        .map_err(|_| io::Error::from(ErrorKind::InvalidData))?;
    }
    Err(err) if err.kind() == ErrorKind::WouldBlock => {
      // Spurious wakeup
    }
    err @ Err(_) => {
      // If we failed to read, try a last-gasp write to send a reason to the other side. This behaves in the
      // same way that the rustls Connection::complete_io() method would.
      _ = try_write(tcp, tls).await;
      err?;
    }
  }
  Ok(())
}

async fn try_write<'a, 'b>(
  tcp: &'a mut TcpStream,
  tls: &'b mut Connection,
) -> io::Result<()> {
  match write_tls(tcp, tls) {
    Ok(_) => {}
    Err(err) if err.kind() == ErrorKind::WouldBlock => {
      // Spurious wakeup
    }
    err @ Err(_) => {
      err?;
    }
  }
  Ok(())
}

/// Performs a handshake and returns the [`TcpStream`]/[`Connection`] pair if successful.
pub async fn handshake_task(
  tcp: TcpStream,
  tls: Connection,
) -> io::Result<(TcpStream, Connection)> {
  handshake_task_internal(tcp, tls, TestOptions::default()).await
}

pub(crate) async fn handshake_task_internal(
  mut tcp: TcpStream,
  mut tls: Connection,
  test_options: TestOptions,
) -> io::Result<(TcpStream, Connection)> {
  #[cfg(not(test))]
  {
    _ = test_options;
  }

  assert!(tls.is_handshaking());
  // We want to exit this loop when we are no longer handshaking AND we no longer have
  // write interest.
  loop {
    if !tls.is_handshaking() && !tls.wants_write() {
      break;
    }
    if tls.wants_write() {
      tcp.writable().await?;
      #[cfg(test)]
      if test_options.slow_handshake_write {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
      }
      match try_write(&mut tcp, &mut tls).await {
        Ok(()) => {}
        Err(err) => {
          struct WriteSink();

          impl std::io::Write for WriteSink {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
              Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
              Ok(())
            }
          }

          // return Err(err);

          // This is a bit of sleight-of-hand: if the handshake fails to write because the other side is gone
          // or otherwise errors, _BUT_ writing takes us out of handshaking mode, we treat this as a successful
          // handshake and defer the error to later on when someone wants to write data.
          while tls.is_handshaking() && tls.wants_write() {
            _ = tls.write_tls(&mut WriteSink());
          }

          if tls.is_handshaking() {
            // Still handshaking but ran out of write interest, so return the error.
            return Err(err);
          } else {
            // Not handshaking, no write interest, pretend we succeeded and pick up the error later.
            return Ok((tcp, tls));
          }
        }
      }
    }
    if !tls.is_handshaking() && !tls.wants_write() {
      break;
    }
    // TLS may want a read, but if we're not handshaking it doesn't help us make progress -- we'll stay in
    // this loop while we flush writes. Note that these signals changed subtly between rustls 0.20 and
    // rustls 0.21 (in the former we didn't need the `tls.wants_read()` test).
    if tls.is_handshaking() && tls.wants_read() {
      tcp.readable().await?;
      #[cfg(test)]
      if test_options.slow_handshake_read {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
      }
      try_read(&mut tcp, &mut tls).await?;
    }
  }
  Ok((tcp, tls))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::tests::client_config;
  use crate::tests::server_config;
  use crate::tests::server_name;
  use crate::tests::TestResult;
  use rustls::ClientConnection;
  use rustls::ServerConnection;
  use tokio::spawn;

  #[tokio::test]
  async fn test_handshake() -> TestResult {
    let (server, client) = crate::tests::tcp_pair().await;
    let tls_server = ServerConnection::new(server_config().into())
      .unwrap()
      .into();
    let tls_client =
      ClientConnection::new(client_config().into(), server_name())
        .unwrap()
        .into();
    let server = spawn(handshake_task(server, tls_server));
    let client = spawn(handshake_task(client, tls_client));
    let (tcp_client, tls_client) = client.await.unwrap().unwrap();
    let (tcp_server, tls_server) = server.await.unwrap().unwrap();
    assert!(!tls_client.is_handshaking());
    assert!(!tls_server.is_handshaking());
    // Don't let these drop until the handshake finishes on both sides
    drop(tcp_client);
    drop(tcp_server);
    Ok(())
  }
}
