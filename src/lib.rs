// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
mod adapter;
mod connection_stream;
// mod half;
mod handshake;
mod stream;

#[cfg(test)]
mod system_test;

pub use stream::TlsHandshake;
pub use stream::TlsStream;
pub use stream::TlsStreamRead;
pub use stream::TlsStreamWrite;

/// Re-export the version of rustls we are built on
pub use rustls;

/// Used to modify test timing to expose problems.
#[derive(Copy, Clone, Default)]
struct TestOptions {
  #[cfg(test)]
  delay_handshake: bool,
  #[cfg(test)]
  slow_handshake_read: bool,
  #[cfg(test)]
  slow_handshake_write: bool,
}

macro_rules! trace {
  ($($args:expr),+) => {
    if false && cfg!(feature="trace")
    {
      println!($($args),+);
    }
  };
}

pub(crate) use trace;

#[cfg(test)]
mod tests {
  pub use super::stream::tests::tls_pair;
  pub use super::stream::tests::tls_pair_buffer_size;
  use rustls::client::ServerCertVerified;
  use rustls::client::ServerCertVerifier;
  use rustls::Certificate;
  use rustls::ClientConfig;
  use rustls::PrivateKey;
  use rustls::ServerConfig;
  use rustls::ServerName;
  use std::io;
  use std::io::BufRead;
  use std::net::Ipv4Addr;
  use std::net::SocketAddr;
  use std::net::SocketAddrV4;
  use std::sync::Arc;
  use tokio::net::TcpListener;
  use tokio::net::TcpSocket;
  use tokio::net::TcpStream;
  use tokio::spawn;

  pub type TestResult = Result<(), Box<dyn std::error::Error>>;

  pub struct UnsafeVerifier {}

  impl ServerCertVerifier for UnsafeVerifier {
    fn verify_server_cert(
      &self,
      _end_entity: &Certificate,
      _intermediates: &[Certificate],
      _server_name: &ServerName,
      _scts: &mut dyn Iterator<Item = &[u8]>,
      _ocsp_response: &[u8],
      _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
      Ok(ServerCertVerified::assertion())
    }
  }

  pub fn certificate() -> Certificate {
    let buf_read: &mut dyn BufRead =
      &mut &include_bytes!("testdata/localhost.crt")[..];
    let cert = rustls_pemfile::read_one(buf_read)
      .expect("Failed to load test cert")
      .unwrap();
    match cert {
      rustls_pemfile::Item::X509Certificate(cert) => Certificate(cert),
      _ => {
        panic!("Unexpected item")
      }
    }
  }

  pub fn private_key() -> PrivateKey {
    let buf_read: &mut dyn BufRead =
      &mut &include_bytes!("testdata/localhost.key")[..];
    let cert = rustls_pemfile::read_one(buf_read)
      .expect("Failed to load test key")
      .unwrap();
    match cert {
      rustls_pemfile::Item::PKCS8Key(key) => PrivateKey(key),
      _ => {
        panic!("Unexpected item")
      }
    }
  }

  pub fn server_config() -> ServerConfig {
    ServerConfig::builder()
      .with_safe_defaults()
      .with_no_client_auth()
      .with_single_cert(vec![certificate()], private_key())
      .expect("Failed to build server config")
  }

  pub fn client_config() -> ClientConfig {
    ClientConfig::builder()
      .with_safe_defaults()
      .with_custom_certificate_verifier(Arc::new(UnsafeVerifier {}))
      .with_no_client_auth()
  }

  pub fn server_name() -> ServerName {
    "example.com".try_into().unwrap()
  }

  pub async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
      Ipv4Addr::LOCALHOST,
      0,
    )))
    .await
    .unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = spawn(async move { listener.accept().await.unwrap().0 });
    let client = spawn(async move {
      TcpSocket::new_v4()
        .unwrap()
        .connect(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
        .await
        .unwrap()
    });

    let (server, client) = (server.await.unwrap(), client.await.unwrap());
    (server, client)
  }

  pub fn expect_io_error<T: std::fmt::Debug>(
    e: Result<T, io::Error>,
    kind: io::ErrorKind,
  ) {
    assert_eq!(e.expect_err("Expected error").kind(), kind);
  }
}
