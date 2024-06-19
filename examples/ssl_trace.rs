use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls_tokio_stream::TlsStream;
use std::env;
use std::sync::Arc;
use tokio::net::TcpStream;

#[derive(Debug)]
pub struct UnsafeVerifier {}

impl ServerCertVerifier for UnsafeVerifier {
  fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
    vec![rustls::SignatureScheme::RSA_PKCS1_SHA1]
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

#[tokio::main]
pub async fn main() {
  #[cfg(feature = "trace")]
  rustls_tokio_stream::enable_byte_tracing();
  rustls::crypto::ring::default_provider().install_default().unwrap();

  let mut args = env::args();
  _ = args.next();
  let address = args.next().expect("Missing host argument");
  let port = args
    .next()
    .expect("Missing port argument")
    .parse::<u16>()
    .expect("Could not parse port");

  println!("Connecting...");
  let tcp = TcpStream::connect(format!("{address}:{port}"))
    .await
    .expect("Could not connect");
  println!("Initiating TLS...");
  let config = ClientConfig::builder()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(UnsafeVerifier {}))
    .with_no_client_auth();
  let mut stm = TlsStream::new_client_side(
    tcp,
    ClientConnection::new(
      Arc::new(config),
      ServerName::try_from(address)
        .expect("Failed to parse address as a server name"),
    )
    .unwrap(),
    None,
  );

  println!("Handshake result: {:?}", stm.handshake().await);
}
