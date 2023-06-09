// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

use crate::connection_stream::ConnectionStream;
use crate::handshake;
use crate::handshake::handshake_task;
use futures::future::poll_fn;
use futures::task::noop_waker;
use futures::task::noop_waker_ref;
use futures::task::AtomicWaker;
use futures::task::Context;
use futures::task::Poll;
use futures::task::RawWaker;
use futures::task::RawWakerVTable;
use futures::task::Waker;
use futures::FutureExt;
use parking_lot::Mutex;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::Connection;
use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::ServerName;
use std::cell::Cell;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Weak;
use std::task::ready;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::oneshot;
use tokio::sync::watch;
use tokio::task::JoinHandle;

enum TlsStreamState {
  /// If we are handshaking, writes are buffered and reads block.
  // TODO(mmastrac): We should be buffered in the Connection, not the Vec, as this results in a double-copy.
  Handshaking(
    JoinHandle<io::Result<(TcpStream, Connection)>>,
    Cell<Option<Waker>>,
    Vec<u8>,
  ),
  /// The connection is open.
  Open(ConnectionStream),
  /// The connection is closed.
  Closed,
}

pub struct TlsStream {
  state: TlsStreamState,
  handshake: watch::Receiver<Option<io::Result<TlsHandshake>>>,
}

#[derive(Clone)]
pub struct TlsHandshake {
  alpn: Option<Vec<u8>>,
}

impl TlsStream {
  fn new(tcp: TcpStream, mut tls: Connection) -> Self {
    tls.set_buffer_limit(None);

    let (tx, handshake) = watch::channel(None);

    // TODO(mmastrac): We're using a oneshot to notify the reader, but this could be more efficient
    let handle = spawn(async move {
      let res = handshake_task(tcp, tls).await;
      match &res {
        Ok(res) => {
          let alpn = res.1.alpn_protocol().map(|v| v.to_owned());
          _ = tx.send(Some(Ok(TlsHandshake { alpn })));
        }
        Err(err) => {
          let kind = err.kind();
          _ = tx.send(Some(Err(kind.into())));
        }
      }

      res
    });

    Self {
      state: TlsStreamState::Handshaking(handle, Cell::new(None), vec![]),
      handshake,
    }
  }

  pub fn new_client_side(
    tcp: TcpStream,
    tls_config: Arc<ClientConfig>,
    server_name: ServerName,
  ) -> Self {
    let tls = ClientConnection::new(tls_config, server_name).unwrap();
    Self::new(tcp, Connection::Client(tls))
  }

  pub fn new_client_side_from(
    tcp: TcpStream,
    connection: ClientConnection,
  ) -> Self {
    Self::new(tcp, Connection::Client(connection))
  }

  pub fn new_server_side(
    tcp: TcpStream,
    tls_config: Arc<ServerConfig>,
  ) -> Self {
    let tls = ServerConnection::new(tls_config).unwrap();
    Self::new(tcp, Connection::Server(tls))
  }

  pub fn new_server_side_from(
    tcp: TcpStream,
    connection: ServerConnection,
  ) -> Self {
    Self::new(tcp, Connection::Server(connection))
  }

  // pub fn into_inner(mut self) -> (TcpStream, Connection) {
  //   let inner = self.0.take().unwrap();
  //   (inner.tcp, inner.tls)
  // }

  // pub fn into_split(self) -> (ReadHalf, WriteHalf) {
  //   let shared = Shared::new(self);
  //   let rd = ReadHalf {
  //     shared: shared.clone(),
  //   };
  //   let wr = WriteHalf { shared };
  //   (rd, wr)
  // }

  // /// Convenience method to match [`TcpStream`].
  // pub fn peer_addr(&self) -> Result<SocketAddr, io::Error> {
  //   self.0.as_ref().unwrap().tcp.peer_addr()
  // }

  // /// Convenience method to match [`TcpStream`].
  // pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
  //   self.0.as_ref().unwrap().tcp.local_addr()
  // }

  // /// Tokio-rustls compatibility: returns a reference to the underlying TCP
  // /// stream, and a reference to the Rustls `Connection` object.
  // pub fn get_ref(&self) -> (&TcpStream, &Connection) {
  //   let inner = self.0.as_ref().unwrap();
  //   (&inner.tcp, &inner.tls)
  // }

  // fn inner_mut(&mut self) -> &mut TlsStreamInner {
  //   self.0.as_mut().unwrap()
  // }

  pub async fn handshake(&mut self) -> io::Result<TlsHandshake> {
    // TODO(mmastrac): Handshake shouldn't need to be cloned
    let Ok(handshake) = self.handshake.wait_for(|r| r.is_some()).await else {
      return Err(io::ErrorKind::NotConnected.into());
    };
    let handshake = handshake.as_ref().expect("Should be Some");
    match handshake {
      Ok(h) => Ok(h.clone()),
      Err(err) => Err(err.kind().into()),
    }
  }

  /// If the handshake is complete, migrate from a pending handshake to the open state.
  fn poll_pending_handshake(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    loop {
      match &mut self.state {
        TlsStreamState::Handshaking(ref mut handle, ref waker, buf) => {
          let res = ready!(handle.poll_unpin(cx));
          match res {
            Err(err) => {
              if err.is_panic() {
                // Resume the panic on the main task
                std::panic::resume_unwind(err.into_panic());
              } else {
                unreachable!("Task should not have been cancelled");
              }
            }
            Ok(Err(err)) => {
              return Poll::Ready(Err(err));
            }
            Ok(Ok((tcp, tls))) => {
              let mut stm = ConnectionStream::new(tcp, tls);
              // We need to save all the data we wrote before the connection. The stream has an internal buffer
              // that matches our buffer, so it can accept it all.
              if let Poll::Ready(Ok(len)) = stm.poll_write(cx, &buf) {
                assert_eq!(len, buf.len());
              } else {
                unreachable!("TLS stream should have accepted entire buffer");
              }
              self.state = TlsStreamState::Open(stm);
              continue;
            }
          }
        }
        _ => {
          return Poll::Ready(Ok(()));
        }
      }
    }
  }

  // fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
  //   match &mut self.0 {
  //     TlsStreamState::Handshaking(_, waker, _) => {
  //       waker.register(cx.waker());
  //       Poll::Pending
  //     },
  //     _ => Poll::Ready(Ok(()))
  //   }
  // }

  // pub fn get_alpn_protocol(&mut self) -> Option<&[u8]> {
  //   self.inner_mut().tls.alpn_protocol()
  // }

  // pub async fn shutdown(&mut self) -> io::Result<()> {
  //   poll_fn(|cx| self.inner_mut().poll_shutdown(cx)).await
  // }

  // pub async fn flush(&mut self) -> io::Result<()> {
  //   poll_fn(|cx| self.inner_mut().poll_flush(cx)).await
  // }

  // pub async fn close(mut self) -> io::Result<()> {
  //   let mut inner = self.0.take().unwrap();
  //   while !poll_fn(|cx| inner.poll_close(cx)).await? {}
  //   Ok(())
  // }

  /// Shuts the connection down, optionally waiting for the handshake to complete.
  fn poll_shutdown_or_abort(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    abort: bool,
  ) -> Poll<io::Result<()>> {
    let res = if abort {
      // If we're still handshaking, abort
      match self.poll_pending_handshake(cx) {
        Poll::Pending => {
          self.state = TlsStreamState::Closed;
          return Poll::Ready(Ok(()));
        }
        Poll::Ready(res) => res,
      }
    } else {
      ready!(self.poll_pending_handshake(cx))
    };

    if res.is_err() {
      // ?
      self.state = TlsStreamState::Closed
    }

    match &mut self.state {
      // Handshaking: drop the handshake and return ready.
      TlsStreamState::Handshaking(..) => {
        unreachable!()
      }
      TlsStreamState::Open(stm) => {
        let res = ready!(stm.poll_shutdown(cx));
        // Because we're in shutdown, we will eat errors
        // TODO: error
        Poll::Ready(Ok(()))
      }
      // Closed: return ready.
      TlsStreamState::Closed => Poll::Ready(Ok(())),
    }
  }
}

impl AsyncRead for TlsStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    match ready!(self.poll_pending_handshake(cx)) {
      Ok(()) => {}
      Err(err) => {
        self.state = TlsStreamState::Closed;
        // TODO: error
        return Poll::Ready(Ok(()));
      }
    };
    match &mut self.state {
      TlsStreamState::Handshaking(..) => {
        unreachable!()
      }
      TlsStreamState::Open(ref mut stm) => {
        match std::task::ready!(stm.poll_read(cx, buf)) {
          Ok(n) => {
            // TODO: n?
            return Poll::Ready(Ok(()));
          }
          Err(err) => {
            return Poll::Ready(Err(err));
          }
        }
      }
      TlsStreamState::Closed => {
        // TODO(mmastrac): Should we differentiate between failed and non-failed close?
        return Poll::Ready(Ok(()));
      }
    }
  }
}

impl AsyncWrite for TlsStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    // TODO: upgrade from handshaking if done
    match &mut self.state {
      TlsStreamState::Handshaking(_, _, write_buf) => {
        write_buf.extend_from_slice(buf);
        return Poll::Ready(Ok(buf.len()));
      }
      TlsStreamState::Open(ref mut stm) => stm.poll_write(cx, buf),
      TlsStreamState::Closed => {
        Poll::Ready(Err(ErrorKind::NotConnected.into()))
      }
    }
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    match &mut self.state {
      TlsStreamState::Handshaking(..) => Poll::Ready(Ok(())),
      TlsStreamState::Closed => {
        Poll::Ready(Err(ErrorKind::NotConnected.into()))
      }
      TlsStreamState::Open(stm) => stm.poll_flush(cx),
    }
  }

  fn poll_shutdown(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), io::Error>> {
    self.poll_shutdown_or_abort(cx, false)
  }
}

impl Drop for TlsStream {
  fn drop(&mut self) {
    let state = std::mem::replace(&mut self.state, TlsStreamState::Closed);
    match state {
      TlsStreamState::Handshaking(handle, _, buf) => {
        spawn(async move {
          if let Ok(Ok((tcp, tls))) = handle.await {
            let mut stm = ConnectionStream::new(tcp, tls);
            poll_fn(|cx| stm.poll_write(cx, &buf)).await;
            poll_fn(|cx| stm.poll_shutdown(cx)).await;
          }
        });
      }
      TlsStreamState::Open(mut stm) => {
        spawn(async move {
          poll_fn(|cx| stm.poll_shutdown(cx)).await;
        });
      }
      TlsStreamState::Closed => {
        // Nothing
      }
    }
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
  use tokio::select;
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

  fn private_key() -> PrivateKey {
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

  fn server_config(alpn: &[&str]) -> ServerConfig {
    let mut config = ServerConfig::builder()
      .with_safe_defaults()
      .with_no_client_auth()
      .with_single_cert(vec![certificate()], private_key())
      .expect("Failed to build server config");
    config.alpn_protocols =
      alpn.iter().map(|v| v.as_bytes().to_owned()).collect();
    config
  }

  fn client_config(alpn: &[&str]) -> ClientConfig {
    let mut config = ClientConfig::builder()
      .with_safe_defaults()
      .with_custom_certificate_verifier(Arc::new(UnsafeVerifier {}))
      .with_no_client_auth();
    config.alpn_protocols =
      alpn.iter().map(|v| v.as_bytes().to_owned()).collect();
    config
  }

  async fn tcp_pair() -> (TcpStream, TcpStream) {
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

  async fn tls_pair() -> (TlsStream, TlsStream) {
    let (server, client) = tcp_pair().await;
    let server = TlsStream::new_server_side(server, server_config(&[]).into());
    let client = TlsStream::new_client_side(
      client,
      client_config(&[]).into(),
      "example.com".try_into().unwrap(),
    );

    (server, client)
  }

  async fn tls_pair_alpn(
    server_alpn: &[&str],
    client_alpn: &[&str],
  ) -> (TlsStream, TlsStream) {
    let (server, client) = tcp_pair().await;
    let server =
      TlsStream::new_server_side(server, server_config(server_alpn).into());
    let client = TlsStream::new_client_side(
      client,
      client_config(client_alpn).into(),
      "example.com".try_into().unwrap(),
    );

    (server, client)
  }

  async fn tls_pair_handshake(
    server_alpn: &[&str],
    client_alpn: &[&str],
  ) -> (TlsStream, TlsStream) {
    let (mut server, mut client) =
      tls_pair_alpn(server_alpn, client_alpn).await;
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

  fn expect_io_error<T: std::fmt::Debug>(
    e: Result<T, io::Error>,
    kind: io::ErrorKind,
  ) {
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

  /// Test that automatic state transition works: send and receive work as expected without waiting
  /// for the handshake
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

  /// Test that the handshake works, and we get the correct ALPN negotiated values.
  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_client_server_alpn() -> TestResult {
    let (mut server, mut client) =
      tls_pair_alpn(&["a", "b", "c"], &["b"]).await;
    let a = spawn(async move {
      let handshake = server.handshake().await.unwrap();
      assert_eq!(handshake.alpn, Some("b".as_bytes().to_vec()));
      server.write_all(b"hello?").await.unwrap();
      let mut buf = [0; 6];
      server.read_exact(&mut buf).await.unwrap();
      assert_eq!(buf.as_slice(), b"hello!");
    });
    let b = spawn(async move {
      let handshake = client.handshake().await.unwrap();
      assert_eq!(handshake.alpn, Some("b".as_bytes().to_vec()));
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
  // #[ntest::timeout(60000)]
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
  // #[ntest::timeout(60000)]
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
  // #[ntest::timeout(60000)]
  async fn test_server_shutdown_after_handshake() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let a = spawn(async move {
      // Shut down after the handshake
      server.handshake().await.unwrap();
      server.shutdown().await.unwrap();
      tx.send(()).unwrap();
      expect_io_error(
        server.write_all(b"hello?").await,
        io::ErrorKind::NotConnected,
      );
    });
    let b = spawn(async move {
      // assert!(client.get_ref().1.is_handshaking());
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
  // #[ntest::timeout(60000)]
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
      let (server, mut client) = tls_pair_handshake(&[], &[]).await;
      drop(server);
      // Can't read -- server shut down (but it was graceful)
      expect_eof_read(&mut client).await;
      Ok(())
    }

    #[tokio::test]
    #[ntest::timeout(60000)]
    async fn test_server_dropped_after_handshake_with_write() -> TestResult {
      let (mut server, mut client) = tls_pair_handshake(&[], &[]).await;
      server.write_all(b"XYZ").await.unwrap();
      drop(server);
      // Can't read -- server shut down (but it was graceful)
      let mut buf: [u8; 10] = [0; 10];
      assert_eq!(client.read(&mut buf).await.unwrap(), 3);
      Ok(())
    }

  //   #[tokio::test]
  //   #[ntest::timeout(60000)]
  //   async fn test_client_dropped() -> TestResult {
  //     let (mut server, client) = tls_pair().await;
  //     drop(client);
  //     // The client will spawn a task to complete the handshake and then go away
  //     server.handshake().await?;
  //     // Can't read -- server shut down (but it was graceful)
  //     expect_eof_read(&mut server).await;
  //     Ok(())
  //   }

  //   #[tokio::test]
  //   #[ntest::timeout(60000)]
  //   async fn test_server_crash() -> TestResult {
  //     let (server, mut client) = tls_pair().await;
  //     let (mut tcp, _tls) = server.into_inner();
  //     tcp.shutdown().await?;

  //     expect_io_error(client.handshake().await, ErrorKind::UnexpectedEof);
  //     // Can't read -- server shut down. Because this happened before the handshake, it's an unexpected EOF.
  //     expect_io_error_read(&mut client, ErrorKind::UnexpectedEof).await;
  //     Ok(())
  //   }

  //   #[tokio::test]
  //   #[ntest::timeout(60000)]
  //   async fn test_server_crash_no_handshake() -> TestResult {
  //     let (server, mut client) = tls_pair().await;
  //     let (mut tcp, _tls) = server.into_inner();
  //     tcp.shutdown().await?;

  //     // Can't read -- server shut down. Because this happened before the handshake, it's an unexpected EOF.
  //     expect_io_error_read(&mut client, ErrorKind::UnexpectedEof).await;
  //     Ok(())
  //   }

  //   #[tokio::test]
  //   #[ntest::timeout(60000)]
  //   async fn test_server_crash_after_handshake() -> TestResult {
  //     let (server, mut client) = tls_pair_handshake().await;

  //     let (mut tcp, _tls) = server.into_inner();
  //     tcp.shutdown().await?;
  //     drop(tcp);

  //     // Can't read -- server shut down. While it wasn't graceful, we should not get an error here.
  //     expect_eof_read(&mut client).await;
  //     Ok(())
  //   }

  //   #[tokio::test(flavor = "current_thread")]
  //   #[ntest::timeout(60000)]
  //   async fn large_transfer_with_shutdown() -> TestResult {
  //     const BUF_SIZE: usize = 10 * 1024;
  //     const BUF_COUNT: usize = 1024;

  //     let (mut server, mut client) = tls_pair_handshake().await;
  //     let a = spawn(async move {
  //       // Heap allocate a large buffer and send it
  //       let buf = vec![42; BUF_COUNT * BUF_SIZE];
  //       server.write_all(&buf).await.unwrap();
  //       server.shutdown().await.unwrap();
  //       server.close().await.unwrap();
  //     });
  //     let b = spawn(async move {
  //       for _ in 0..BUF_COUNT {
  //         tokio::time::sleep(Duration::from_millis(1)).await;
  //         let mut buf = [0; BUF_SIZE];
  //         assert_eq!(BUF_SIZE, client.read_exact(&mut buf).await.unwrap());
  //       }
  //       expect_eof_read(&mut client).await;
  //     });
  //     a.await?;
  //     b.await?;
  //     Ok(())
  //   }

  //   #[tokio::test(flavor = "current_thread")]
  //   #[ntest::timeout(60000)]
  //   async fn large_transfer_no_shutdown() -> TestResult {
  //     const BUF_SIZE: usize = 10 * 1024;
  //     const BUF_COUNT: usize = 1024;

  //     let (mut server, mut client) = tls_pair_handshake().await;
  //     let a = spawn(async move {
  //       // Heap allocate a large buffer and send it
  //       let buf = vec![42; BUF_COUNT * BUF_SIZE];
  //       server.write_all(&buf).await.unwrap();
  //       server.close().await.unwrap();
  //     });
  //     let b = spawn(async move {
  //       for _ in 0..BUF_COUNT {
  //         tokio::time::sleep(Duration::from_millis(1)).await;
  //         let mut buf = [0; BUF_SIZE];
  //         assert_eq!(BUF_SIZE, client.read_exact(&mut buf).await.unwrap());
  //       }
  //       expect_eof_read(&mut client).await;
  //     });
  //     a.await?;
  //     b.await?;
  //     Ok(())
  //   }

  //   #[tokio::test(flavor = "current_thread")]
  //   async fn large_transfer_drop_socket_after_flush() -> TestResult {
  //     const BUF_SIZE: usize = 10 * 1024;
  //     const BUF_COUNT: usize = 1024;
  //     const LAST_COUNT: usize = 512;

  //     let (mut server, mut client) = tls_pair_handshake().await;
  //     // let (tx, rx) = tokio::sync::oneshot::channel();
  //     let a = spawn(async move {
  //       // Heap allocate a large buffer and send it
  //       let buf = vec![42; BUF_COUNT * BUF_SIZE];
  //       let (mut rd, mut wr) = server.into_split();
  //       let rd = spawn(async move { rd.read_u8().await });
  //       wr.write_all(&buf).await.unwrap();
  //       wr.flush().await.unwrap();
  //       // let (mut tcp, _tls) = server.into_inner();
  //       wr.shutdown().await.unwrap();
  //       drop(wr);
  //       // drop(tcp);
  //       rd.await;
  //     });
  //     let b = spawn(async move {
  //       tokio::time::sleep(Duration::from_millis(109)).await;
  //       for i in 0..BUF_COUNT {
  //         tokio::time::sleep(Duration::from_millis(10)).await;
  //         let mut buf = [0; BUF_SIZE];
  //         assert_eq!(
  //           BUF_SIZE,
  //           client
  //             .read_exact(&mut buf)
  //             .await
  //             .expect(&format!("After reading {i} packets"))
  //         );
  //       }
  //     });
  //     a.await?;
  //     b.await?;
  //     Ok(())
  //   }
}
