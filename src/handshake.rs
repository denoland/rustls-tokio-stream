// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
use rustls::Connection;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;

use tokio::net::TcpStream;

use crate::adapter::read_tls;
use crate::adapter::rustls_to_io_error;
use crate::adapter::write_tls;
use crate::trace;
use crate::TestOptions;

#[inline(always)]
fn trace_result<T>(result: io::Result<T>) -> io::Result<T> {
  #[cfg(feature = "trace")]
  if let Err(err) = &result {
    trace!("result = {err:?}");
  }
  result
}

fn try_read(tcp: &TcpStream, tls: &mut Connection) -> io::Result<()> {
  match read_tls(tcp, tls) {
    Ok(0) => {
      // EOF during handshake
      return Err(ErrorKind::UnexpectedEof.into());
    }
    Ok(_) => {
      tls.process_new_packets().map_err(rustls_to_io_error)?;
    }
    Err(err) if err.kind() == ErrorKind::WouldBlock => {
      // Spurious wakeup
    }
    err @ Err(_) => {
      err?;
    }
  }
  Ok(())
}

fn try_write(tcp: &TcpStream, tls: &mut Connection) -> io::Result<()> {
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

#[derive(Debug)]
pub(crate) struct HandshakeResult(Arc<TcpStream>, pub Connection);

impl HandshakeResult {
  #[cfg(test)]
  pub fn reclaim(self) -> (TcpStream, Connection) {
    (
      Arc::into_inner(self.0).expect("Failed to reclaim TCP"),
      self.1,
    )
  }

  // TODO(mmastrac): if we split ConnectionStream we can remove the Arc and use reclaim2
  #[allow(unused)]
  pub fn reclaim2(self, tcp: Arc<TcpStream>) -> (TcpStream, Connection) {
    drop(tcp);
    (
      Arc::into_inner(self.0).expect("Failed to reclaim TCP"),
      self.1,
    )
  }

  pub fn into_inner(self) -> (Arc<TcpStream>, Connection) {
    (self.0, self.1)
  }
}

/// Performs a handshake and returns the [`TcpStream`]/[`Connection`] pair if successful.
pub(crate) async fn handshake_task(
  tcp: Arc<TcpStream>,
  tls: Connection,
  test_options: TestOptions,
) -> io::Result<HandshakeResult> {
  let res = handshake_task_internal(tcp, tls, test_options).await;
  // Ensure consistency in handshake errors
  match res {
    #[cfg(windows)]
    Err(err) if err.kind() == ErrorKind::ConnectionAborted => {
      Err(ErrorKind::UnexpectedEof.into())
    }
    #[cfg(target_os = "macos")]
    Err(err) if err.kind() == ErrorKind::ConnectionReset => {
      Err(ErrorKind::UnexpectedEof.into())
    }
    r => r,
  }
}

async fn handshake_task_internal(
  tcp: Arc<TcpStream>,
  mut tls: Connection,
  test_options: TestOptions,
) -> io::Result<HandshakeResult> {
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
      trace_result(tcp.writable().await)?;
      #[cfg(test)]
      if test_options.slow_handshake_write {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
      }
      match try_write(&tcp, &mut tls) {
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
            return Ok(HandshakeResult(tcp, tls));
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
      trace_result(tcp.readable().await)?;
      #[cfg(test)]
      if test_options.slow_handshake_read {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
      }
      match try_read(&tcp, &mut tls) {
        Ok(_) => {}
        Err(err) => {
          trace!("read error {err:?}, starting last gasp write");
          // If we failed to read, try a last-gasp write to send a reason to the other side. This behaves in the
          // same way that the rustls Connection::complete_io() method would.
          while tls.wants_write() {
            trace_result(tcp.writable().await)?;
            match try_write(&tcp, &mut tls) {
              Err(err) if err.kind() == ErrorKind::WouldBlock => {
                // Spurious wakeup
                continue;
              }
              Err(_) => break,
              Ok(_) => {}
            }
          }
          return Err(err);
        }
      }
    }
  }
  Ok(HandshakeResult(tcp, tls))
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
  use tokio::task::spawn;

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
    let server = spawn(handshake_task(
      server.into(),
      tls_server,
      TestOptions::default(),
    ));
    let client = spawn(handshake_task(
      client.into(),
      tls_client,
      TestOptions::default(),
    ));
    let (tcp_client, tls_client) = client.await.unwrap().unwrap().reclaim();
    let (tcp_server, tls_server) = server.await.unwrap().unwrap().reclaim();
    assert!(!tls_client.is_handshaking());
    assert!(!tls_server.is_handshaking());
    // Don't let these drop until the handshake finishes on both sides
    drop(tcp_client);
    drop(tcp_server);
    Ok(())
  }
}
