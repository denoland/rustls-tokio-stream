use rustls::Connection;
use std::io;
use std::io::ErrorKind;
use tokio::net::TcpStream;

use crate::adapter::read_tls;
use crate::adapter::write_tls;

async fn try_read<'a, 'b>(tcp: &'a mut TcpStream, tls: &'b mut Connection) -> io::Result<()> {
    match read_tls(tcp, tls) {
        Ok(n) => {
            tls.process_new_packets()
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

async fn try_write<'a, 'b>(tcp: &'a mut TcpStream, tls: &'b mut Connection) -> io::Result<()> {
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
    mut tcp: TcpStream,
    mut tls: Connection,
) -> io::Result<(TcpStream, Connection)> {
    assert!(tls.is_handshaking());
    // We want to exit this loop when we are no longer handshaking AND we no longer have
    // write interest.
    loop {
        if !tls.is_handshaking() && !tls.wants_write() {
            break;
        }
        if tls.wants_write() {
            tcp.writable().await?;
            try_write(&mut tcp, &mut tls).await?;
        }
        if !tls.is_handshaking() && !tls.wants_write() {
            break;
        }
        if tls.wants_read() {
            tcp.readable().await?;
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
        let tls_client = ClientConnection::new(client_config().into(), server_name())
            .unwrap()
            .into();
        let server = spawn(handshake_task(server, tls_server));
        let client = spawn(handshake_task(client, tls_client));
        let (_, tls_client) = client.await.unwrap().unwrap();
        let (_, tls_server) = server.await.unwrap().unwrap();
        assert!(!tls_client.is_handshaking());
        assert!(!tls_server.is_handshaking());
        Ok(())
    }
}
