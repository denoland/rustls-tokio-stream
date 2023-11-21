use rustls::client::ServerCertVerified;
use rustls::client::ServerCertVerifier;
use rustls::server::DnsName;
use rustls::Certificate;
use rustls::ClientConfig;
use rustls::ServerName;
use rustls_tokio_stream::TlsStream;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

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

#[tokio::main]
pub async fn main() {
  #[cfg(feature = "trace")]
  rustls_tokio_stream::enable_byte_tracing();

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
    .with_safe_defaults()
    .with_custom_certificate_verifier(Arc::new(UnsafeVerifier {}))
    .with_no_client_auth();
  let mut stm = TlsStream::new_client_side(
    tcp,
    Arc::new(config),
    ServerName::try_from(address.as_str())
      .expect("Failed to parse address as a server name"),
    None,
  );

  println!("Handshake result: {:?}", stm.handshake().await);
}
