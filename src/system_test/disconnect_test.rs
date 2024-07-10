use crate::tests::certificate;
use crate::tests::private_key;
use crate::TlsStream;
use rustls::server::ClientHello;
use rustls::ServerConfig;
use std::io;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpSocket;
use tokio::net::TcpListener;
use tokio::spawn;

fn alpn_handler(
  client_hello: ClientHello,
) -> Result<&'static [&'static str], &'static str> {
  if let Some(alpn) = client_hello.alpn() {
    for alpn in alpn {
      if alpn == b"a" {
        return Ok(&["a"]);
      }
      if alpn == b"b" {
        return Ok(&["b"]);
      }
    }
  }
  Err("bad server")
}

fn server_config_alpn(alpn: &[&str]) -> ServerConfig {
  let mut config = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(vec![certificate()], private_key())
    .expect("Failed to build server config");
  config.alpn_protocols =
    alpn.iter().map(|v| v.as_bytes().to_owned()).collect();
  config
}

async fn make_config(
  alpn: Result<&'static [&'static str], &'static str>,
) -> Result<Arc<ServerConfig>, io::Error> {
  Ok(
    server_config_alpn(
      alpn.map_err(|e| io::Error::new(std::io::ErrorKind::InvalidData, e))?,
    )
    .into(),
  )
}

#[tokio::test]
async fn disconnect_test() {
  let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
    Ipv4Addr::LOCALHOST,
    0,
  )))
  .await
  .unwrap();

  let port = listener.local_addr().unwrap().port();

  let _client = spawn(async move {
    TcpSocket::new_v4()
      .unwrap()
      .connect(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
      .await
      .unwrap()
  });

  let server = listener.accept().await.unwrap().0;
  let mut client = _client.await.unwrap();

  client.shutdown().await.expect("Shutdown failed"); // Disconnect before tls handshake

  TlsStream::new_server_side_acceptor(
    server,
    Arc::new(move |client_hello| {
      Box::pin(make_config(alpn_handler(client_hello)))
    }),
    None
  );

  // At this point, the acceptor is in an infinite loop, to test if it's really so, try to connect another client.

  spawn(async move {
    TcpSocket::new_v4()
      .unwrap()
      .connect(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
      .await
      .unwrap()
  }).await.unwrap();

  listener.accept().await.unwrap().0; // The test should be stuck now if the bug is still active
}
