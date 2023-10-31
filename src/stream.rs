// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

use crate::connection_stream::ConnectionStream;
use crate::handshake::handshake_task_internal;
use crate::trace;
use crate::TestOptions;
use futures::future::poll_fn;
use futures::task::noop_waker_ref;
use futures::task::Context;
use futures::task::Poll;
use futures::task::Waker;
use futures::FutureExt;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::Connection;
use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::ServerName;
use std::cell::Cell;
use std::fmt::Debug;
use std::io;
use std::io::ErrorKind;
use std::io::Write;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::ready;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::watch;
use tokio::task::JoinError;
use tokio::task::JoinHandle;

#[derive(Clone, Default)]
struct SharedWaker(Rc<Cell<Option<Waker>>>);
unsafe impl Send for SharedWaker {}

impl SharedWaker {
  pub fn wake(&self) {
    if let Some(waker) = self.0.take() {
      waker.wake();
    }
  }

  pub fn set_waker(&self, waker: &Waker) {
    self.0.set(Some(waker.clone()))
  }
}

enum TlsStreamState {
  /// If we are handshaking, writes are buffered and reads block.
  // TODO(mmastrac): We should be buffered in the Connection, not the Vec, as this results in a double-copy.
  Handshaking {
    handle: JoinHandle<io::Result<(TcpStream, Connection)>>,
    read_waker: SharedWaker,
    write_waker: SharedWaker,
    write_buf: Vec<u8>,
  },
  /// The connection is open.
  Open(ConnectionStream),
  /// The connection is closed.
  Closed,
  /// The connection is closed because of an error.
  ClosedError(ErrorKind),
}

pub struct TlsStream {
  state: TlsStreamState,

  handshake: watch::Receiver<Option<io::Result<TlsHandshake>>>,
  buffer_size: Option<NonZeroUsize>,
}

impl Debug for TlsStream {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match &self.state {
      TlsStreamState::Handshaking { .. } => {
        f.write_str("TlsStream { Handshaking }")
      }
      TlsStreamState::Open(..) => f.write_fmt(format_args!(
        "TlsStream {{ Open, handshake: {:?} }}",
        self.handshake.borrow()
      )),
      TlsStreamState::Closed => f.write_str("TlsStream { Closed }"),
      TlsStreamState::ClosedError(err) => {
        f.write_fmt(format_args!("TlsStream {{ Closed, error: {:?} }}", err))
      }
    }
  }
}

#[derive(Clone, Debug)]
pub struct TlsHandshake {
  pub alpn: Option<Vec<u8>>,
}

impl TlsStream {
  fn new(
    tcp: TcpStream,
    mut tls: Connection,
    buffer_size: Option<NonZeroUsize>,
    test_options: TestOptions,
  ) -> Self {
    tls.set_buffer_limit(buffer_size.map(|s| s.get()));

    let (tx, handshake) = watch::channel(None);
    let read_waker = SharedWaker::default();
    let write_waker = SharedWaker::default();
    let read_waker_clone = read_waker.clone();
    let write_waker_clone = write_waker.clone();

    // This task does nothing but yield a TlsHandshake to a oneshot
    let handle = spawn(async move {
      #[cfg(test)]
      if test_options.delay_handshake {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
      }
      let res = handshake_task_internal(tcp, tls, test_options).await;
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

      // We may have read/writes blocked on the handshake, so wake them all up
      read_waker_clone.wake();
      write_waker_clone.wake();

      res
    });

    Self {
      state: TlsStreamState::Handshaking {
        handle,
        read_waker,
        write_waker,
        write_buf: vec![],
      },
      handshake,
      buffer_size,
    }
  }

  pub fn new_client_side(
    tcp: TcpStream,
    tls_config: Arc<ClientConfig>,
    server_name: ServerName,
    buffer_size: Option<NonZeroUsize>,
  ) -> Self {
    let tls = ClientConnection::new(tls_config, server_name).unwrap();
    Self::new(
      tcp,
      Connection::Client(tls),
      buffer_size,
      TestOptions::default(),
    )
  }

  #[cfg(test)]
  pub(crate) fn new_client_side_test_options(
    tcp: TcpStream,
    tls_config: Arc<ClientConfig>,
    server_name: ServerName,
    buffer_size: Option<NonZeroUsize>,
    test_options: TestOptions,
  ) -> Self {
    let tls = ClientConnection::new(tls_config, server_name).unwrap();
    Self::new(tcp, Connection::Client(tls), buffer_size, test_options)
  }

  pub fn new_client_side_from(
    tcp: TcpStream,
    connection: ClientConnection,
    buffer_size: Option<NonZeroUsize>,
  ) -> Self {
    Self::new(
      tcp,
      Connection::Client(connection),
      buffer_size,
      TestOptions::default(),
    )
  }

  #[cfg(test)]
  pub(crate) fn new_server_side_test_options(
    tcp: TcpStream,
    tls_config: Arc<ServerConfig>,
    buffer_size: Option<NonZeroUsize>,
    test_options: TestOptions,
  ) -> Self {
    let tls = ServerConnection::new(tls_config).unwrap();
    Self::new(tcp, Connection::Server(tls), buffer_size, test_options)
  }

  pub fn new_server_side(
    tcp: TcpStream,
    tls_config: Arc<ServerConfig>,
    buffer_size: Option<NonZeroUsize>,
  ) -> Self {
    let tls = ServerConnection::new(tls_config).unwrap();
    Self::new(
      tcp,
      Connection::Server(tls),
      buffer_size,
      TestOptions::default(),
    )
  }

  pub fn new_server_side_from(
    tcp: TcpStream,
    connection: ServerConnection,
    buffer_size: Option<NonZeroUsize>,
  ) -> Self {
    Self::new(
      tcp,
      Connection::Server(connection),
      buffer_size,
      TestOptions::default(),
    )
  }

  /// Attempt to retrieve the inner stream and connection.
  pub fn try_into_inner(mut self) -> Result<(TcpStream, Connection), Self> {
    match self.state {
      TlsStreamState::Open(_) => {
        let TlsStreamState::Open(stm) =
          std::mem::replace(&mut self.state, TlsStreamState::Closed)
        else {
          unreachable!()
        };
        Ok(stm.into_inner())
      }
      _ => Err(self),
    }
  }

  pub async fn into_inner(mut self) -> io::Result<(TcpStream, Connection)> {
    poll_fn(|cx| self.poll_pending_handshake(cx)).await?;
    match std::mem::replace(&mut self.state, TlsStreamState::Closed) {
      TlsStreamState::Open(stm) => Ok(stm.into_inner()),
      TlsStreamState::Closed => Err(ErrorKind::NotConnected.into()),
      TlsStreamState::ClosedError(err) => Err(err.into()),
      TlsStreamState::Handshaking { .. } => unreachable!(),
    }
  }

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

  fn finalize_handshake(
    &mut self,
    join_result: Result<io::Result<(TcpStream, Connection)>, JoinError>,
  ) -> io::Result<()> {
    trace!("finalize handshake");
    match &mut self.state {
      TlsStreamState::Handshaking {
        read_waker,
        write_waker,
        write_buf: buf,
        ..
      } => {
        match join_result {
          Err(err) => {
            if err.is_panic() {
              // Resume the panic on the main task
              std::panic::resume_unwind(err.into_panic());
            } else {
              unreachable!("Task should not have been cancelled");
            }
          }
          Ok(Err(err)) => Err(err),
          Ok(Ok((tcp, tls))) => {
            let mut stm = ConnectionStream::new(tcp, tls);
            trace!("hs buf={}", buf.len());
            // We need to save all the data we wrote before the connection. The stream has an internal buffer
            // that matches our buffer, so it can accept it all.
            stm.write_buf_fully(buf);
            read_waker.wake();
            write_waker.wake();
            self.state = TlsStreamState::Open(stm);
            Ok(())
          }
        }
      }
      _ => unreachable!(),
    }
  }

  /// If the handshake is complete, migrate from a pending handshake to the open state.
  fn poll_pending_handshake(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    match &mut self.state {
      TlsStreamState::Handshaking { handle, .. } => {
        let res = ready!(handle.poll_unpin(cx));
        Poll::Ready(self.finalize_handshake(res))
      }
      _ => Poll::Ready(Ok(())),
    }
  }

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

    if let Err(err) = res {
      self.state = TlsStreamState::ClosedError(err.kind());
    }

    match &mut self.state {
      // Handshaking: drop the handshake and return ready.
      TlsStreamState::Handshaking { .. } => {
        unreachable!()
      }
      TlsStreamState::Open(stm) => {
        let _res = ready!(stm.poll_shutdown(cx));
        // Because we're in shutdown, we will eat errors
        // TODO: error
        Poll::Ready(Ok(()))
      }
      // Closed: return ready.
      TlsStreamState::Closed => Poll::Ready(Ok(())),
      // Closed: return error.
      TlsStreamState::ClosedError(err) => Poll::Ready(Err((*err).into())),
    }
  }

  pub async fn close(mut self) -> io::Result<()> {
    let state = std::mem::replace(&mut self.state, TlsStreamState::Closed);
    trace!("closing {self:?}");
    match state {
      TlsStreamState::Handshaking {
        handle,
        read_waker,
        write_waker,
        write_buf: buf,
      } => {
        read_waker.wake();
        write_waker.wake();
        match handle.await {
          Ok(Ok((tcp, tls))) => {
            let mut stm = ConnectionStream::new(tcp, tls);
            poll_fn(|cx| stm.poll_write(cx, &buf)).await?;
            poll_fn(|cx| stm.poll_shutdown(cx)).await?;
          }
          Err(err) => {
            if err.is_panic() {
              // Resume the panic on the main task
              std::panic::resume_unwind(err.into_panic());
            } else {
              unreachable!("Task should not have been cancelled");
            }
          }
          Ok(Err(err)) => {
            return Err(err);
          }
        }
      }
      TlsStreamState::Open(mut stm) => {
        poll_fn(|cx| stm.poll_shutdown(cx)).await?;
      }
      TlsStreamState::Closed | TlsStreamState::ClosedError(_) => {
        // Nothing
      }
    }

    Ok(())
  }
}

impl AsyncRead for TlsStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    loop {
      break match &mut self.state {
        TlsStreamState::Handshaking {
          handle, read_waker, ..
        } => {
          // If the handshake completed, we want to finalize it and then continue
          if handle.is_finished() {
            let Poll::Ready(res) =
              handle.poll_unpin(&mut Context::from_waker(noop_waker_ref()))
            else {
              unreachable!()
            };
            self.finalize_handshake(res)?;
            continue;
          }

          // Handshake is still blocking us
          read_waker.set_waker(cx.waker());
          Poll::Pending
        }
        TlsStreamState::Open(ref mut stm) => {
          match std::task::ready!(stm.poll_read(cx, buf)) {
            Ok(_n) => {
              // TODO: n?
              Poll::Ready(Ok(()))
            }
            Err(err) => Poll::Ready(Err(err)),
          }
        }
        TlsStreamState::Closed => Poll::Ready(Ok(())),
        TlsStreamState::ClosedError(err) => Poll::Ready(Err((*err).into())),
      };
    }
  }
}

impl AsyncWrite for TlsStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    let buffer_size = self.buffer_size;
    loop {
      break match &mut self.state {
        TlsStreamState::Handshaking {
          handle,
          write_waker,
          write_buf,
          ..
        } => {
          // If the handshake completed, we want to finalize it and then continue
          if handle.is_finished() {
            let Poll::Ready(res) =
              handle.poll_unpin(&mut Context::from_waker(noop_waker_ref()))
            else {
              unreachable!()
            };
            self.finalize_handshake(res)?;
            continue;
          }
          if let Some(buffer_size) = buffer_size {
            let remaining = buffer_size.get() - write_buf.len();
            if remaining == 0 {
              // No room to write, so store the waker for whenever the handshake is done
              write_waker.set_waker(cx.waker());
              trace!("write limit");
              Poll::Pending
            } else {
              trace!("write buf");
              if buf.len() <= remaining {
                write_buf.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
              } else {
                write_buf.extend_from_slice(&buf[0..remaining]);
                Poll::Ready(Ok(remaining))
              }
            }
          } else {
            trace!("write buf");
            write_buf.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
          }
        }
        TlsStreamState::Open(ref mut stm) => stm.poll_write(cx, buf),
        TlsStreamState::Closed => {
          Poll::Ready(Err(ErrorKind::NotConnected.into()))
        }
        TlsStreamState::ClosedError(err) => Poll::Ready(Err((*err).into())),
      };
    }
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    match &mut self.state {
      TlsStreamState::Handshaking { .. } => Poll::Ready(Ok(())),
      TlsStreamState::Open(stm) => stm.poll_flush(cx),
      TlsStreamState::Closed => {
        Poll::Ready(Err(ErrorKind::NotConnected.into()))
      }
      TlsStreamState::ClosedError(err) => Poll::Ready(Err((*err).into())),
    }
  }

  fn is_write_vectored(&self) -> bool {
    true
  }

  fn poll_write_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[std::io::IoSlice<'_>],
  ) -> Poll<Result<usize, io::Error>> {
    let buffer_size = self.buffer_size;
    loop {
      break match &mut self.state {
        TlsStreamState::Handshaking {
          handle,
          write_waker,
          write_buf,
          ..
        } => {
          // If the handshake completed, we want to finalize it and then continue
          if handle.is_finished() {
            let Poll::Ready(res) =
              handle.poll_unpin(&mut Context::from_waker(noop_waker_ref()))
            else {
              unreachable!()
            };
            self.finalize_handshake(res)?;
            continue;
          }
          if let Some(buffer_size) = buffer_size {
            let mut remaining = buffer_size.get() - write_buf.len();
            if remaining == 0 {
              // No room to write, so store the waker for whenever the handshake is done
              write_waker.set_waker(cx.waker());
              trace!("write limit");
              Poll::Pending
            } else {
              trace!("write buf");
              let mut wrote = 0;
              for buf in bufs {
                if buf.len() <= remaining {
                  write_buf.extend_from_slice(buf);
                  wrote += buf.len();
                  remaining -= buf.len();
                } else {
                  write_buf.extend_from_slice(&buf[0..remaining]);
                  wrote += remaining;
                  break;
                }
              }

              // TODO(mmastrac): this currently ignores remaining size
              Poll::Ready(Ok(wrote))
            }
          } else {
            trace!("write buf");
            Poll::Ready(Ok(write_buf.write_vectored(bufs).unwrap()))
          }
        }
        TlsStreamState::Open(ref mut stm) => stm.poll_write_vectored(cx, bufs),
        TlsStreamState::Closed => {
          Poll::Ready(Err(ErrorKind::NotConnected.into()))
        }
        TlsStreamState::ClosedError(err) => Poll::Ready(Err((*err).into())),
      };
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
    trace!("dropping {self:?}");
    let state = std::mem::replace(&mut self.state, TlsStreamState::Closed);
    match state {
      TlsStreamState::Handshaking {
        handle, write_buf, ..
      } => {
        spawn(async move {
          trace!("in task");
          match handle.await {
            Ok(Ok((tcp, tls))) => {
              let mut stm = ConnectionStream::new(tcp, tls);
              stm.write_buf_fully(&write_buf);
              trace!("{:?}", poll_fn(|cx| stm.poll_shutdown(cx)).await);
            }
            x @ Err(_) => {
              trace!("{x:?}");
            }
            x @ Ok(Err(_)) => {
              trace!("{x:?}");
            }
          }
          trace!("done task");
        });
      }
      TlsStreamState::Open(mut stm) => {
        spawn(async move {
          trace!("in task");
          trace!("{:?}", poll_fn(|cx| stm.poll_shutdown(cx)).await);
          trace!("done task");
        });
      }
      TlsStreamState::Closed | TlsStreamState::ClosedError(_) => {
        // Nothing
      }
    }
  }
}

#[cfg(test)]
pub(super) mod tests {
  use super::*;
  use crate::tests::expect_io_error;
  use futures::stream::FuturesUnordered;
  use futures::FutureExt;
  use futures::StreamExt;
  use rstest::rstest;
  use rustls::client::ServerCertVerified;
  use rustls::client::ServerCertVerifier;
  use rustls::Certificate;
  use rustls::PrivateKey;
  use std::io::BufRead;
  use std::io::ErrorKind;
  use std::net::Ipv4Addr;
  use std::net::SocketAddr;
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

  pub async fn tls_pair() -> (TlsStream, TlsStream) {
    tls_pair_buffer_size(None).await
  }

  pub async fn tls_pair_buffer_size(
    buffer_size: Option<NonZeroUsize>,
  ) -> (TlsStream, TlsStream) {
    let (server, client) = tcp_pair().await;
    let server =
      TlsStream::new_server_side(server, server_config(&[]).into(), None);
    let client = TlsStream::new_client_side(
      client,
      client_config(&[]).into(),
      "example.com".try_into().unwrap(),
      buffer_size,
    );

    (server, client)
  }

  async fn tls_with_tcp_client() -> (TlsStream, TcpStream) {
    let (server, client) = tcp_pair().await;
    let server =
      TlsStream::new_server_side(server, server_config(&[]).into(), None);
    (server, client)
  }

  async fn tls_with_tcp_server() -> (TcpStream, TlsStream) {
    let (server, client) = tcp_pair().await;
    let client = TlsStream::new_client_side(
      client,
      client_config(&[]).into(),
      "example.com".try_into().unwrap(),
      None,
    );
    (server, client)
  }

  async fn tls_pair_slow_handshake(
    delay_handshake: bool,
    slow_server: bool,
    slow_client: bool,
  ) -> (TlsStream, TlsStream) {
    let (server, client) = tcp_pair().await;
    let server_test_options = TestOptions {
      delay_handshake,
      slow_handshake_read: slow_server,
      slow_handshake_write: slow_server,
    };
    let client_test_options = TestOptions {
      delay_handshake,
      slow_handshake_read: slow_client,
      slow_handshake_write: slow_client,
    };
    let server = TlsStream::new_server_side_test_options(
      server,
      server_config(&[]).into(),
      None,
      server_test_options,
    );
    let client = TlsStream::new_client_side_test_options(
      client,
      client_config(&[]).into(),
      "example.com".try_into().unwrap(),
      None,
      client_test_options,
    );

    (server, client)
  }

  async fn tls_pair_alpn(
    server_alpn: &[&str],
    server_buffer_size: Option<NonZeroUsize>,
    client_alpn: &[&str],
    client_buffer_size: Option<NonZeroUsize>,
  ) -> (TlsStream, TlsStream) {
    let (server, client) = tcp_pair().await;
    let server = TlsStream::new_server_side(
      server,
      server_config(server_alpn).into(),
      server_buffer_size,
    );
    let client = TlsStream::new_client_side(
      client,
      client_config(client_alpn).into(),
      "example.com".try_into().unwrap(),
      client_buffer_size,
    );

    (server, client)
  }

  async fn tls_pair_handshake_buffer_size(
    server_buffer_size: Option<NonZeroUsize>,
    client_buffer_size: Option<NonZeroUsize>,
  ) -> (TlsStream, TlsStream) {
    let (mut server, mut client) =
      tls_pair_alpn(&[], server_buffer_size, &[], client_buffer_size).await;
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

  async fn tls_pair_handshake() -> (TlsStream, TlsStream) {
    tls_pair_handshake_buffer_size(None, None).await
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
  #[rstest]
  #[case(false, false)]
  #[case(false, true)]
  #[case(true, false)]
  #[case(true, true)]
  #[tokio::test]
  async fn test_client_server(
    #[case] server_slow: bool,
    #[case] client_slow: bool,
  ) -> TestResult {
    let (mut server, mut client) =
      tls_pair_slow_handshake(false, server_slow, client_slow).await;
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
      tls_pair_alpn(&["a", "b", "c"], None, &["b"], None).await;
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

  #[rstest]
  #[case(false, false)]
  #[case(false, true)]
  #[case(true, false)]
  #[case(true, true)]
  #[tokio::test]
  async fn test_client_immediate_close(
    #[case] server_slow: bool,
    #[case] client_slow: bool,
  ) -> TestResult {
    let (mut server, client) =
      tls_pair_slow_handshake(false, server_slow, client_slow).await;
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

  // ---- stream::tests::test_server_immediate_close stdout ----
  // w=Ok(242)
  // r(4096)=Ok(242)
  // w=Ok(127)
  // w=Ok(6)
  // w=Ok(32)
  // w=Ok(913)
  // w=Ok(286)
  // w=Ok(74)
  // r(4096)=Err(Kind(WouldBlock))
  // r(4096)=Ok(1438)
  // w=Ok(6)
  // w=Ok(74)
  // w=Ok(24)
  // r(4096)=Err(Kind(WouldBlock))
  // r(4096)=Ok(80)
  // w=Ok(103)
  // w=Ok(103)
  // w=Ok(103)
  // w=Ok(103)
  // w=Ok(24)
  // r(4096)=Ok(103)
  // r*=Kind(WouldBlock)
  // r(4096)=Err(Os { code: 54, kind: ConnectionReset, message: "Connection reset by peer" })
  // r*=Kind(WouldBlock)
  // thread 'stream::tests::test_server_immediate_close' panicked at 'Expected no error: Kind(ConnectionReset)', src/stream.rs:548:38
  // note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
  // Error: Custom { kind: Other, error: "task panicked" }

  #[rstest]
  #[case(false, false)]
  #[case(false, true)]
  #[case(true, false)]
  #[case(true, true)]
  #[tokio::test]
  async fn test_server_immediate_close(
    #[case] server_slow: bool,
    #[case] client_slow: bool,
  ) -> TestResult {
    let (server, mut client) =
      tls_pair_slow_handshake(false, server_slow, client_slow).await;
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

  #[rstest]
  #[case(false, false)]
  #[case(false, true)]
  #[case(true, false)]
  #[case(true, true)]
  #[tokio::test]
  async fn test_orderly_shutdown(
    #[case] server_slow: bool,
    #[case] client_slow: bool,
  ) -> TestResult {
    let (mut server, mut client) =
      tls_pair_slow_handshake(false, server_slow, client_slow).await;
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

  #[rstest]
  #[case(false, false)]
  #[case(false, true)]
  #[case(true, false)]
  #[case(true, true)]
  #[tokio::test]
  async fn test_server_shutdown_after_handshake(
    #[case] server_slow: bool,
    #[case] client_slow: bool,
  ) -> TestResult {
    let (mut server, mut client) =
      tls_pair_slow_handshake(false, server_slow, client_slow).await;
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

  #[rstest]
  #[case(false, false)]
  #[case(false, true)]
  #[case(true, false)]
  #[case(true, true)]
  #[tokio::test]
  async fn test_server_shutdown_before_handshake(
    #[case] server_slow: bool,
    #[case] client_slow: bool,
  ) -> TestResult {
    let (mut server, mut client) =
      tls_pair_slow_handshake(false, server_slow, client_slow).await;
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

  #[rstest]
  #[case(false, false)]
  #[case(false, true)]
  #[case(true, false)]
  #[case(true, true)]
  #[tokio::test]
  async fn test_server_dropped(
    #[case] server_slow: bool,
    #[case] client_slow: bool,
  ) -> TestResult {
    let (server, mut client) =
      tls_pair_slow_handshake(false, server_slow, client_slow).await;
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

  #[rstest]
  #[case(false, false)]
  #[case(false, true)]
  #[case(true, false)]
  #[case(true, true)]
  #[tokio::test]
  async fn test_client_dropped(
    #[case] server_slow: bool,
    #[case] client_slow: bool,
  ) -> TestResult {
    let (mut server, client) =
      tls_pair_slow_handshake(false, server_slow, client_slow).await;
    drop(client);
    // The client will spawn a task to complete the handshake and then go away
    server.handshake().await?;
    // Can't read -- server shut down (but it was graceful)
    expect_eof_read(&mut server).await;
    Ok(())
  }

  #[tokio::test]
  async fn test_server_half_crash_before_handshake() -> TestResult {
    let (mut server, mut client) = tls_with_tcp_server().await;
    // This test occasionally shows up as ConnectionReset on Mac -- the delay ensures we wait long enough
    // for the handshake to settle.
    tokio::time::sleep(Duration::from_millis(100)).await;
    server.shutdown().await?;

    let expected = ErrorKind::UnexpectedEof;

    expect_io_error(client.handshake().await, expected);
    // Can't read -- server shut down. Because this happened before the handshake, it's an unexpected EOF.
    expect_io_error_read(&mut client, expected).await;
    Ok(())
  }

  #[tokio::test]
  async fn test_server_crash_before_handshake() -> TestResult {
    let (mut server, mut client) = tls_with_tcp_server().await;
    server.shutdown().await?;
    drop(server);

    let expected = if cfg!(target_os = "windows") {
      ErrorKind::ConnectionAborted
    } else if cfg!(target_os = "macos") {
      // TODO(mmastrac): this is occasionally `UnexpectedEof` on mac
      ErrorKind::ConnectionReset
    } else {
      ErrorKind::UnexpectedEof
    };
    expect_io_error(client.handshake().await, expected);
    // Can't read -- server shut down. Because this happened before the handshake, we get the underlying
    // error here.
    expect_io_error_read(&mut client, expected).await;
    Ok(())
  }

  #[tokio::test]
  async fn test_server_crash_after_handshake() -> TestResult {
    let (server, mut client) = tls_pair_handshake().await;

    let (mut tcp, _tls) = server.into_inner().await.unwrap();
    tcp.shutdown().await?;
    drop(tcp);

    // Can't read -- server shut down. This is an unexpected EOF.
    expect_io_error_read(&mut client, ErrorKind::UnexpectedEof).await;
    Ok(())
  }

  #[tokio::test]
  async fn large_transfer_no_buffer_limit_or_handshake() -> TestResult {
    const BUF_SIZE: usize = 64 * 1024;
    const BUF_COUNT: usize = 1024;

    let (mut server, mut client) = tls_pair().await;
    let a = spawn(async move {
      // Heap allocate a large buffer and send it
      let buf = vec![42; BUF_COUNT * BUF_SIZE];
      server.write_all(&buf).await.unwrap();
      assert_eq!(server.read_u8().await.unwrap(), 0xff);
      server.shutdown().await.unwrap();
      server.close().await.unwrap();
    });
    let b = spawn(async move {
      for _ in 0..BUF_COUNT {
        tokio::time::sleep(Duration::from_millis(1)).await;
        let mut buf = [0; BUF_SIZE];
        assert_eq!(BUF_SIZE, client.read_exact(&mut buf).await.unwrap());
      }
      client.write_u8(0xff).await.unwrap();
      expect_eof_read(&mut client).await;
    });
    a.await?;
    b.await?;
    Ok(())
  }

  #[tokio::test]
  async fn large_transfer_with_buffer_limit() -> TestResult {
    const BUF_SIZE: usize = 10 * 1024;
    const BUF_COUNT: usize = 1024;

    let (mut server, mut client) = tls_pair_handshake_buffer_size(
      BUF_SIZE.try_into().ok(),
      BUF_SIZE.try_into().ok(),
    )
    .await;
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
