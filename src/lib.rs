// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

use crate::inner::Flow;
use crate::inner::State;
use crate::inner::TlsStreamInner;
use futures::future::poll_fn;
use futures::task::AtomicWaker;
use futures::task::Context;
use futures::task::Poll;
use futures::task::RawWaker;
use futures::task::RawWakerVTable;
use futures::task::Waker;
use parking_lot::Mutex;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::Connection;
use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::ServerName;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Weak;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;
use tokio::spawn;

mod inner;

pub struct TlsStream(Option<TlsStreamInner>);

impl TlsStream {
  fn new(tcp: TcpStream, mut tls: Connection) -> Self {
    tls.set_buffer_limit(None);

    let inner = TlsStreamInner {
      tcp,
      tls,
      rd_state: State::StreamOpen,
      wr_state: State::StreamOpen,
    };
    Self(Some(inner))
  }

  pub fn new_client_side(
    tcp: TcpStream,
    tls_config: Arc<ClientConfig>,
    server_name: ServerName,
  ) -> Self {
    let tls = ClientConnection::new(tls_config, server_name).unwrap();
    Self::new(tcp, Connection::Client(tls))
  }

  pub fn new_client_side_from(tcp: TcpStream, connection: ClientConnection) -> Self {
    Self::new(tcp, Connection::Client(connection))
  }

  pub fn new_server_side(tcp: TcpStream, tls_config: Arc<ServerConfig>) -> Self {
    let tls = ServerConnection::new(tls_config).unwrap();
    Self::new(tcp, Connection::Server(tls))
  }

  pub fn new_server_side_from(tcp: TcpStream, connection: ServerConnection) -> Self {
    Self::new(tcp, Connection::Server(connection))
  }

  pub fn into_inner(mut self) -> (TcpStream, Connection) {
    let inner = self.0.take().unwrap();
    (inner.tcp, inner.tls)
  }

  pub fn into_split(self) -> (ReadHalf, WriteHalf) {
    let shared = Shared::new(self);
    let rd = ReadHalf {
      shared: shared.clone(),
    };
    let wr = WriteHalf { shared };
    (rd, wr)
  }

  /// Convenience method to match [`TcpStream`].
  pub fn peer_addr(&self) -> Result<SocketAddr, io::Error> {
    self.0.as_ref().unwrap().tcp.peer_addr()
  }

  /// Convenience method to match [`TcpStream`].
  pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
    self.0.as_ref().unwrap().tcp.local_addr()
  }

  /// Tokio-rustls compatibility: returns a reference to the underlying TCP
  /// stream, and a reference to the Rustls `Connection` object.
  pub fn get_ref(&self) -> (&TcpStream, &Connection) {
    let inner = self.0.as_ref().unwrap();
    (&inner.tcp, &inner.tls)
  }

  fn inner_mut(&mut self) -> &mut TlsStreamInner {
    self.0.as_mut().unwrap()
  }

  pub async fn handshake(&mut self) -> io::Result<()> {
    poll_fn(|cx| self.inner_mut().poll_handshake(cx)).await
  }

  fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.inner_mut().poll_handshake(cx)
  }

  pub fn get_alpn_protocol(&mut self) -> Option<&[u8]> {
    self.inner_mut().tls.alpn_protocol()
  }

  pub async fn shutdown(&mut self) -> io::Result<()> {
    poll_fn(|cx| self.inner_mut().poll_shutdown(cx)).await
  }

  pub async fn close(mut self) -> io::Result<()> {
    let mut inner = self.0.take().unwrap();
    while !poll_fn(|cx| inner.poll_close(cx)).await? {}
    Ok(())
  }
}

impl AsyncRead for TlsStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    self.inner_mut().poll_read(cx, buf)
  }
}

impl AsyncWrite for TlsStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    self.inner_mut().poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.inner_mut().poll_io(cx, Flow::Write)
    // The underlying TCP stream does not need to be flushed.
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.inner_mut().poll_shutdown(cx)
  }
}

impl Drop for TlsStream {
  fn drop(&mut self) {
    let Some(mut inner) = self.0.take() else {
      return;
    };

    // If read and write are closed, we can fast exit here
    if inner.wr_state != State::StreamOpen && inner.rd_state != State::StreamOpen {
      return;
    }

    let tls = &inner.tls;
    if (tls.is_handshaking() && tls.wants_read()) || tls.wants_write() {
      spawn(async move {
        // If we get Ok(true) or Err(..) from poll_close, abort the loop and let the TCP connection
        // drop.
        while let Ok(false) = poll_fn(|cx| inner.poll_close(cx)).await {}
      });
    }
  }
}

pub struct ReadHalf {
  shared: Arc<Shared>,
}

impl ReadHalf {
  pub fn reunite(self, wr: WriteHalf) -> TlsStream {
    assert!(Arc::ptr_eq(&self.shared, &wr.shared));
    drop(wr); // Drop `wr`, so only one strong reference to `shared` remains.

    Arc::try_unwrap(self.shared)
      .unwrap_or_else(|_| panic!("Arc::<Shared>::try_unwrap() failed"))
      .tls_stream
      .into_inner()
  }
}

impl AsyncRead for ReadHalf {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    self
      .shared
      .poll_with_shared_waker(cx, Flow::Read, move |tls, cx| tls.poll_read(cx, buf))
  }
}

pub struct WriteHalf {
  shared: Arc<Shared>,
}

impl WriteHalf {
  pub async fn handshake(&mut self) -> io::Result<()> {
    poll_fn(|cx| {
      self
        .shared
        .poll_with_shared_waker(cx, Flow::Write, |mut tls, cx| tls.poll_handshake(cx))
    })
    .await
  }

  pub async fn shutdown(&mut self) -> io::Result<()> {
    poll_fn(move |cx| {
      self
        .shared
        .poll_with_shared_waker(cx, Flow::Shutdown, |tls, cx| tls.poll_shutdown(cx))
    })
    .await
  }

  pub fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
    self.shared.get_alpn_protocol()
  }
}

impl AsyncWrite for WriteHalf {
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    self
      .shared
      .poll_with_shared_waker(cx, Flow::Write, move |tls, cx| tls.poll_write(cx, buf))
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self
      .shared
      .poll_with_shared_waker(cx, Flow::Write, |tls, cx| tls.poll_flush(cx))
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self
      .shared
      .poll_with_shared_waker(cx, Flow::Shutdown, |tls, cx| tls.poll_shutdown(cx))
  }
}

struct Shared {
  tls_stream: Mutex<TlsStream>,
  rd_waker: AtomicWaker,
  wr_waker: AtomicWaker,
}

impl Shared {
  fn new(tls_stream: TlsStream) -> Arc<Self> {
    let self_ = Self {
      tls_stream: Mutex::new(tls_stream),
      rd_waker: AtomicWaker::new(),
      wr_waker: AtomicWaker::new(),
    };
    Arc::new(self_)
  }

  fn poll_with_shared_waker<R>(
    self: &Arc<Self>,
    cx: &mut Context<'_>,
    flow: Flow,
    mut f: impl FnMut(Pin<&mut TlsStream>, &mut Context<'_>) -> R,
  ) -> R {
    match flow {
      Flow::Handshake => unreachable!(),
      Flow::Read => self.rd_waker.register(cx.waker()),
      Flow::Write | Flow::Shutdown => self.wr_waker.register(cx.waker()),
    }

    let shared_waker = self.new_shared_waker();
    let mut cx = Context::from_waker(&shared_waker);

    let mut tls_stream = self.tls_stream.lock();
    f(Pin::new(&mut tls_stream), &mut cx)
  }

  const SHARED_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    Self::clone_shared_waker,
    Self::wake_shared_waker,
    Self::wake_shared_waker_by_ref,
    Self::drop_shared_waker,
  );

  fn new_shared_waker(self: &Arc<Self>) -> Waker {
    let self_weak = Arc::downgrade(self);
    let self_ptr = self_weak.into_raw() as *const ();
    let raw_waker = RawWaker::new(self_ptr, &Self::SHARED_WAKER_VTABLE);
    // TODO(bartlomieju):
    #[allow(clippy::undocumented_unsafe_blocks)]
    unsafe {
      Waker::from_raw(raw_waker)
    }
  }

  fn clone_shared_waker(self_ptr: *const ()) -> RawWaker {
    // TODO(bartlomieju):
    #[allow(clippy::undocumented_unsafe_blocks)]
    let self_weak = unsafe { Weak::from_raw(self_ptr as *const Self) };
    let ptr1 = self_weak.clone().into_raw();
    let ptr2 = self_weak.into_raw();
    assert!(ptr1 == ptr2);
    RawWaker::new(self_ptr, &Self::SHARED_WAKER_VTABLE)
  }

  fn wake_shared_waker(self_ptr: *const ()) {
    Self::wake_shared_waker_by_ref(self_ptr);
    Self::drop_shared_waker(self_ptr);
  }

  fn wake_shared_waker_by_ref(self_ptr: *const ()) {
    // TODO(bartlomieju):
    #[allow(clippy::undocumented_unsafe_blocks)]
    let self_weak = unsafe { Weak::from_raw(self_ptr as *const Self) };
    if let Some(self_arc) = Weak::upgrade(&self_weak) {
      self_arc.rd_waker.wake();
      self_arc.wr_waker.wake();
    }
    let _ = self_weak.into_raw();
  }

  fn drop_shared_waker(self_ptr: *const ()) {
    // TODO(bartlomieju):
    #[allow(clippy::undocumented_unsafe_blocks)]
    let _ = unsafe { Weak::from_raw(self_ptr as *const Self) };
  }

  fn get_alpn_protocol(self: &Arc<Self>) -> Option<Vec<u8>> {
    let mut tls_stream = self.tls_stream.lock();
    tls_stream.get_alpn_protocol().map(|s| s.to_vec())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use futures::stream::FuturesUnordered;
  use futures::FutureExt;
  use futures::StreamExt;
  use rustls::client::ServerCertVerified;
  use rustls::client::ServerCertVerifier;
  use rustls::Certificate;
  use rustls::PrivateKey;
  use std::io::BufRead;
  use std::io::ErrorKind;
  use std::net::Ipv4Addr;
  use std::net::SocketAddrV4;
  use std::time::Duration;
  use tokio::io::AsyncReadExt;
  use tokio::io::AsyncWriteExt;
  use tokio::net::TcpListener;
  use tokio::net::TcpSocket;
  use tokio::spawn;

  type TestResult = Result<(), std::io::Error>;

  struct UnsafeVerifier {}

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

  fn certificate() -> Certificate {
    let buf_read: &mut dyn BufRead = &mut &include_bytes!("testdata/localhost.crt")[..];
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

  fn private_key() -> PrivateKey {
    let buf_read: &mut dyn BufRead = &mut &include_bytes!("testdata/localhost.key")[..];
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
      .with_custom_certificate_verifier(Arc::new(UnsafeVerifier {}))
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

  async fn tls_pair_handshake() -> (TlsStream, TlsStream) {
    let (mut server, mut client) = tls_pair().await;
    let a = spawn(async move {
      server.handshake().await.unwrap();
      server
    });
    let b = spawn(async move {
      client.handshake().await.unwrap();
      client
    });
    (a.await.unwrap(), b.await.unwrap())
  }

  fn expect_io_error<T: std::fmt::Debug>(e: Result<T, io::Error>, kind: io::ErrorKind) {
    assert_eq!(e.expect_err("Expected error").kind(), kind);
  }

  async fn expect_eof_read(stm: &mut TlsStream) {
    let mut buf = [0_u8; 1];
    let e = stm.read(&mut buf).await.expect("Expected no error");
    assert_eq!(e, 0, "expected eof");
  }

  async fn expect_io_error_read(stm: &mut TlsStream, kind: io::ErrorKind) {
    let mut buf = [0_u8; 1];
    let e = stm.read(&mut buf).await.expect_err("Expected error");
    assert_eq!(e.kind(), kind);
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_client_server() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    let a = spawn(async move {
      server.write_all(b"hello?").await.unwrap();
      let mut buf = [0; 6];
      server.read_exact(&mut buf).await.unwrap();
      assert_eq!(buf.as_slice(), b"hello!");
    });
    let b = spawn(async move {
      client.write_all(b"hello!").await.unwrap();
      let mut buf = [0; 6];
      client.read_exact(&mut buf).await.unwrap();
    });
    a.await?;
    b.await?;

    Ok(())
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_client_immediate_close() -> TestResult {
    let (mut server, client) = tls_pair().await;
    let a = spawn(async move {
      server.shutdown().await.unwrap();
      // While this races the handshake, we are not going to expose a handshake EOF to the stream in a
      // regular read.
      expect_eof_read(&mut server).await;
      drop(server);
    });
    let b = spawn(async move {
      drop(client);
    });
    a.await?;
    b.await?;

    Ok(())
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_server_immediate_close() -> TestResult {
    let (server, mut client) = tls_pair().await;
    let a = spawn(async move {
      drop(server);
    });
    let b = spawn(async move {
      client.shutdown().await.unwrap();
      // While this races the handshake, we are not going to expose a handshake EOF to the stream in a
      // regular read.
      expect_eof_read(&mut client).await;
      drop(client);
    });
    a.await?;
    b.await?;

    Ok(())
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_orderly_shutdown() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let a = spawn(async move {
      server.write_all(b"hello?").await.unwrap();
      let mut buf = [0; 6];
      server.read_exact(&mut buf).await.unwrap();
      assert_eq!(buf.as_slice(), b"hello!");
      // Shut down write, but reads are still open
      server.shutdown().await.unwrap();
      server.read_exact(&mut buf).await.unwrap();
      assert_eq!(buf.as_slice(), b"hello*");
      // Tell the client to shut down at some point after we've closed the server TCP socket.
      drop(server);
      tokio::time::sleep(Duration::from_millis(10)).await;
      tx.send(()).unwrap();
    });
    let b = spawn(async move {
      client.write_all(b"hello!").await.unwrap();
      let mut buf = [0; 6];
      client.read_exact(&mut buf).await.unwrap();
      assert_eq!(client.read(&mut buf).await.unwrap(), 0);
      client.write_all(b"hello*").await.unwrap();
      // The server is long gone by the point we get the message, but it's a clean shutdown
      rx.await.unwrap();
      client.shutdown().await.unwrap();
      drop(client);
    });
    a.await?;
    b.await?;

    Ok(())
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_server_shutdown_after_handshake() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let a = spawn(async move {
      // Shut down after the handshake
      server.handshake().await.unwrap();
      server.shutdown().await.unwrap();
      tx.send(()).unwrap();
      expect_io_error(server.write_all(b"hello?").await, io::ErrorKind::BrokenPipe);
    });
    let b = spawn(async move {
      assert!(client.get_ref().1.is_handshaking());
      client.handshake().await.unwrap();
      rx.await.unwrap();
      // Can't read -- server shut down
      expect_eof_read(&mut client).await;
    });
    a.await?;
    b.await?;

    Ok(())
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_server_shutdown_before_handshake() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    let a = spawn(async move {
      let mut futures = FuturesUnordered::new();

      // The client handshake must complete before the server shutdown is resolved
      futures.push(server.shutdown().map(|_| 1).boxed());
      futures.push(client.handshake().map(|_| 2).boxed());

      assert_eq!(poll_fn(|cx| futures.poll_next_unpin(cx)).await.unwrap(), 2);
      assert_eq!(poll_fn(|cx| futures.poll_next_unpin(cx)).await.unwrap(), 1);
      drop(futures);

      // Can't read -- server shut down
      expect_eof_read(&mut client).await;
    });
    a.await?;

    Ok(())
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_server_dropped() -> TestResult {
    let (server, mut client) = tls_pair().await;
    // The server will spawn a task to complete the handshake and then go away
    drop(server);
    client.handshake().await?;
    // Can't read -- server shut down (but it was graceful)
    expect_eof_read(&mut client).await;
    Ok(())
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_server_dropped_after_handshake() -> TestResult {
    let (server, mut client) = tls_pair_handshake().await;
    drop(server);
    // Can't read -- server shut down (but it was graceful)
    expect_eof_read(&mut client).await;
    Ok(())
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_server_dropped_after_handshake_with_write() -> TestResult {
    let (mut server, mut client) = tls_pair_handshake().await;
    server.write_all(b"XYZ").await.unwrap();
    drop(server);
    // Can't read -- server shut down (but it was graceful)
    let mut buf: [u8; 10] = [0; 10];
    assert_eq!(client.read(&mut buf).await.unwrap(), 3);
    Ok(())
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_client_dropped() -> TestResult {
    let (mut server, client) = tls_pair().await;
    drop(client);
    // The client will spawn a task to complete the handshake and then go away
    server.handshake().await?;
    // Can't read -- server shut down (but it was graceful)
    expect_eof_read(&mut server).await;
    Ok(())
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_server_crash() -> TestResult {
    let (server, mut client) = tls_pair().await;
    let (mut tcp, _tls) = server.into_inner();
    tcp.shutdown().await?;

    expect_io_error(client.handshake().await, ErrorKind::UnexpectedEof);
    // Can't read -- server shut down. Because this happened before the handshake, it's an unexpected EOF.
    expect_io_error_read(&mut client, ErrorKind::UnexpectedEof).await;
    Ok(())
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_server_crash_no_handshake() -> TestResult {
    let (server, mut client) = tls_pair().await;
    let (mut tcp, _tls) = server.into_inner();
    tcp.shutdown().await?;

    // Can't read -- server shut down. Because this happened before the handshake, it's an unexpected EOF.
    expect_io_error_read(&mut client, ErrorKind::UnexpectedEof).await;
    Ok(())
  }

  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_server_crash_after_handshake() -> TestResult {
    let (server, mut client) = tls_pair_handshake().await;

    let (mut tcp, _tls) = server.into_inner();
    tcp.shutdown().await?;
    drop(tcp);

    // Can't read -- server shut down. While it wasn't graceful, we should not get an error here.
    expect_eof_read(&mut client).await;
    Ok(())
  }

  #[tokio::test(flavor = "current_thread")]
  #[ntest::timeout(60000)]
  async fn large_transfer_with_shutdown() -> TestResult {
    const BUF_SIZE: usize = 10 * 1024;
    const BUF_COUNT: usize = 1024;

    let (mut server, mut client) = tls_pair_handshake().await;
    let a = spawn(async move {
      // Heap allocate a large buffer and send it
      let buf = vec![42; BUF_COUNT * BUF_SIZE];
      server.write_all(&buf).await.unwrap();
      server.shutdown().await.unwrap();
      server.close().await.unwrap();
    });
    let b = spawn(async move {
      for _ in 0..BUF_COUNT {
        tokio::time::sleep(Duration::from_millis(1)).await;
        let mut buf = [0; BUF_SIZE];
        assert_eq!(BUF_SIZE, client.read_exact(&mut buf).await.unwrap());
      }
      expect_eof_read(&mut client).await;
    });
    a.await?;
    b.await?;
    Ok(())
  }

  #[tokio::test(flavor = "current_thread")]
  #[ntest::timeout(60000)]
  async fn large_transfer_no_shutdown() -> TestResult {
    const BUF_SIZE: usize = 10 * 1024;
    const BUF_COUNT: usize = 1024;

    let (mut server, mut client) = tls_pair_handshake().await;
    let a = spawn(async move {
      // Heap allocate a large buffer and send it
      let buf = vec![42; BUF_COUNT * BUF_SIZE];
      server.write_all(&buf).await.unwrap();
      server.close().await.unwrap();
    });
    let b = spawn(async move {
      for _ in 0..BUF_COUNT {
        tokio::time::sleep(Duration::from_millis(1)).await;
        let mut buf = [0; BUF_SIZE];
        assert_eq!(BUF_SIZE, client.read_exact(&mut buf).await.unwrap());
      }
      expect_eof_read(&mut client).await;
    });
    a.await?;
    b.await?;
    Ok(())
  }
}
