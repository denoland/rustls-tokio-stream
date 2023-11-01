# rustls-tokio-stream

rustls-tokio-stream is a Rust crate that provides an AsyncRead/AsyncWrite interface for rustls.

Features:

 - Supports duplex I/O via `tokio::io::split` and other methods out-of-the-box
 - Does not require either read or write polling to perform handshakes

## Examples

Create a server and client running on localhost:

```rust
  fn server_config() -> ServerConfig {
    ServerConfig::builder()
      .with_safe_defaults()
      .with_no_client_auth()
      .with_single_cert(vec![certificate()], private_key())
      .expect("Failed to build server config")
  }

  fn client_config() -> ClientConfig {
    ClientConfig::builder()
      .with_safe_defaults()
      .with_no_client_auth()
  }

  async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
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

  async fn tls_pair() -> (TlsStream, TlsStream) {
    let (server, client) = tcp_pair().await;
    let server = TlsStream::new_server_side(server, server_config().into());
    let client = TlsStream::new_client_side(
      client,
      client_config().into(),
      "example.com".try_into().unwrap(),
    );

    (server, client)
  }
```
