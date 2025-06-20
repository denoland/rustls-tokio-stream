// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
mod adapter;
mod connection_stream;
mod handshake;
mod stream;

///! An `async` wrapper around the `rustls` connection types and a `tokio` TCP socket.

#[cfg(test)]
mod system_test;

pub use stream::ServerConfigProvider;
pub use stream::TlsHandshake;
pub use stream::TlsStream;
pub use stream::TlsStreamRead;
pub use stream::TlsStreamWrite;
pub use stream::UnderlyingStream;

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

#[cfg(feature = "trace")]
static ENABLE_BYTE_TRACING: std::sync::atomic::AtomicBool =
  std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "trace")]
pub fn enable_byte_tracing() {
  ENABLE_BYTE_TRACING.store(true, std::sync::atomic::Ordering::SeqCst);
}

macro_rules! trace {
  ($($args:expr),+) => {
    if cfg!(feature="trace")
    {
      print!("[{:?}] ", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
      println!($($args),+);
    }
  };
}

pub(crate) use trace;

#[cfg(test)]
mod tests {
  pub use super::stream::tests::tls_pair;
  pub use super::stream::tests::tls_pair_buffer_size;
  use rustls::client::danger::ServerCertVerified;
  use rustls::client::danger::ServerCertVerifier;
  use rustls::pki_types::CertificateDer;
  use rustls::pki_types::PrivateKeyDer;
  use rustls::pki_types::ServerName;
  use rustls::ClientConfig;
  use rustls::ServerConfig;
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

  #[derive(Debug)]
  pub struct UnsafeVerifier {}

  impl ServerCertVerifier for UnsafeVerifier {
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
      vec![rustls::SignatureScheme::RSA_PSS_SHA256]
    }

    fn verify_tls12_signature(
      &self,
      _message: &[u8],
      _cert: &rustls::pki_types::CertificateDer<'_>,
      _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
      Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
      &self,
      _message: &[u8],
      _cert: &rustls::pki_types::CertificateDer<'_>,
      _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
      Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_server_cert(
      &self,
      _end_entity: &rustls::pki_types::CertificateDer<'_>,
      _intermediates: &[rustls::pki_types::CertificateDer<'_>],
      _server_name: &ServerName<'_>,
      _ocsp_response: &[u8],
      _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
      Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
  }

  pub fn certificate() -> CertificateDer<'static> {
    let buf_read: &mut dyn BufRead =
      &mut &include_bytes!("testdata/localhost.crt")[..];
    let cert = rustls_pemfile::read_one(buf_read)
      .expect("Failed to load test cert")
      .unwrap();
    match cert {
      rustls_pemfile::Item::X509Certificate(cert) => cert,
      _ => {
        panic!("Unexpected item")
      }
    }
  }

  pub fn private_key() -> PrivateKeyDer<'static> {
    let buf_read: &mut dyn BufRead =
      &mut &include_bytes!("testdata/localhost.key")[..];
    let cert = rustls_pemfile::read_one(buf_read)
      .expect("Failed to load test key")
      .unwrap();
    match cert {
      rustls_pemfile::Item::Pkcs8Key(key) => key.into(),
      _ => {
        panic!("Unexpected item")
      }
    }
  }

  pub fn server_config() -> ServerConfig {
    ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(vec![certificate()], private_key())
      .expect("Failed to build server config")
  }

  pub fn client_config() -> ClientConfig {
    ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(UnsafeVerifier {}))
      .with_no_client_auth()
  }

  pub fn server_name() -> ServerName<'static> {
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
