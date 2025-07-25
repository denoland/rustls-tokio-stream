// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

use crate::adapter::clone_error;
use crate::adapter::clone_result;
use crate::adapter::read_acceptor;
use crate::adapter::rustls_to_io_error;
use crate::adapter::write_acceptor_alert;
use crate::connection_stream::ConnectionStream;
use crate::handshake::handshake_task;
use crate::handshake::HandshakeResult;
use crate::trace;
use crate::TestOptions;
use derive_io::AsyncRead;
use derive_io::AsyncWrite;
use futures::task::AtomicWaker;
use futures::FutureExt;
use rustls::server::Acceptor;
use rustls::server::ClientHello;
use rustls::version::TLS13;
use rustls::ClientConnection;
use rustls::Connection;
use rustls::ServerConfig;
use rustls::ServerConnection;
use socket2::SockRef;
use std::any::Any;
use std::fmt::Debug;
use std::future::poll_fn;
use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::io::Write;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use std::task::ready;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::thread::sleep;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::task::spawn_blocking;
use tokio::task::JoinError;
use tokio::task::JoinHandle;

/// The handshake may block read and write operations and requires us to track
/// which wakers are pending so that we can wake them to re-poll their
/// operations after the handshake completes.
#[derive(Clone)]
struct DeferredWakers {
  wakers: Arc<Mutex<DeferredWakersInner>>,
}

#[derive(Default)]
enum DeferredWakersInner {
  /// If the deferred wakers have been woken already, we don't want
  /// to re-register them and instead just wake them in place to
  /// prevent races.
  #[default]
  Woke,
  /// No deferred wakers have been woken.
  Pending(Option<Waker>, Option<Waker>),
}

impl DeferredWakers {
  pub fn wake(&self) {
    match std::mem::take(&mut *self.wakers.lock().unwrap()) {
      DeferredWakersInner::Pending(mut read, mut write) => {
        if let Some(read) = read.take() {
          read.wake();
        }
        if let Some(write) = write.take() {
          write.wake();
        }
      }
      DeferredWakersInner::Woke => {}
    }
  }

  /// Register the read waker if pending, or wake immediately if the deferred wakers have been woken.
  pub fn set_read_waker(&self, waker: &Waker) {
    let mut lock = self.wakers.lock().unwrap();
    match &mut *lock {
      DeferredWakersInner::Pending(read, _write) => *read = Some(waker.clone()),
      DeferredWakersInner::Woke => waker.wake_by_ref(),
    }
  }

  /// Register the write waker if pending, or wake immediately if the deferred wakers have been woken.
  pub fn set_write_waker(&self, waker: &Waker) {
    let mut lock = self.wakers.lock().unwrap();
    match &mut *lock {
      DeferredWakersInner::Pending(_read, write) => {
        *write = Some(waker.clone())
      }
      DeferredWakersInner::Woke => waker.wake_by_ref(),
    }
  }
}

impl Default for DeferredWakers {
  fn default() -> Self {
    Self {
      wakers: Arc::new(Mutex::new(DeferredWakersInner::Pending(None, None))),
    }
  }
}

#[derive(Default)]
struct HandshakeWatch {
  handshake: Mutex<Option<io::Result<TlsHandshake>>>,
  rx_waker: AtomicWaker,
  tx_waker: AtomicWaker,
}

#[allow(clippy::large_enum_variant)]
enum TlsStreamState<S: UnderlyingStream> {
  /// If we are handshaking, writes are buffered and reads block.
  // TODO(mmastrac): We should be buffered in the Connection, not the Vec, as this results in a double-copy.
  Handshaking {
    handle: JoinHandle<io::Result<HandshakeResult<S>>>,
    wakers: DeferredWakers,
    write_buf: Vec<u8>,
    underlying: Arc<S>,
  },
  /// The connection is open.
  Open(ConnectionStream<S>),
  /// The connection is closed.
  Closed,
  /// The connection is closed because of an error.
  ClosedError(io::Error),
}

pub type ServerConfigProvider = Arc<
  dyn Fn(
      ClientHello<'_>,
    ) -> Pin<
      Box<dyn Future<Output = Result<Arc<ServerConfig>, io::Error>> + Send>,
    > + Send
    + Sync,
>;

pub trait UnderlyingStream: Debug + Send + Sync + Sized + 'static {
  type StdType: Send;
  fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
  fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
  fn try_read(&self, buf: &mut [u8]) -> io::Result<usize>;
  fn try_write(&self, buf: &[u8]) -> io::Result<usize>;
  fn readable(&self) -> impl Future<Output = io::Result<()>> + Send;
  fn writable(&self) -> impl Future<Output = io::Result<()>> + Send;

  fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()>;

  fn into_std(self) -> Option<std::io::Result<Self::StdType>> {
    None
  }

  fn downcast<S: UnderlyingStream>(self) -> Result<S, Self> {
    let mut holder = Some(self);
    let stream = &mut holder as &mut dyn Any;
    if let Some(stream) = stream.downcast_mut::<Option<S>>() {
      Ok(stream.take().unwrap())
    } else {
      Err(holder.take().unwrap())
    }
  }
}

impl UnderlyingStream for TcpStream {
  type StdType = std::net::TcpStream;
  #[inline(always)]
  fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.poll_read_ready(cx)
  }
  #[inline(always)]
  fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.poll_write_ready(cx)
  }
  #[inline(always)]
  fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
    self.try_read(buf)
  }
  #[inline(always)]
  fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
    self.try_write(buf)
  }
  #[inline(always)]
  fn readable(&self) -> impl Future<Output = io::Result<()>> + Send {
    self.readable()
  }
  #[inline(always)]
  fn writable(&self) -> impl Future<Output = io::Result<()>> + Send {
    self.writable()
  }
  #[inline(always)]
  fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
    SockRef::from(&self).shutdown(how)
  }
  #[inline(always)]
  fn into_std(self) -> Option<std::io::Result<std::net::TcpStream>> {
    Some(self.into_std())
  }
}

#[cfg(unix)]
impl UnderlyingStream for tokio::net::UnixStream {
  type StdType = std::os::unix::net::UnixStream;
  #[inline(always)]
  fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.poll_read_ready(cx)
  }
  #[inline(always)]
  fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.poll_write_ready(cx)
  }
  #[inline(always)]
  fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
    self.try_read(buf)
  }
  #[inline(always)]
  fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
    self.try_write(buf)
  }
  #[inline(always)]
  fn readable(&self) -> impl Future<Output = io::Result<()>> + Send {
    self.readable()
  }
  #[inline(always)]
  fn writable(&self) -> impl Future<Output = io::Result<()>> + Send {
    self.writable()
  }
  #[inline(always)]
  fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
    SockRef::from(&self).shutdown(how)
  }
  #[inline(always)]
  fn into_std(self) -> Option<std::io::Result<std::os::unix::net::UnixStream>> {
    Some(self.into_std())
  }
}

/// An `async` stream that wraps a `rustls` connection and a TCP socket.
pub struct TlsStream<S: UnderlyingStream> {
  state: TlsStreamState<S>,

  handshake: Arc<HandshakeWatch>,
  buffer_size: Option<NonZeroUsize>,
}

impl<S: UnderlyingStream> Debug for TlsStream<S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match &self.state {
      TlsStreamState::Handshaking { .. } => {
        f.write_str("TlsStream { Handshaking }")
      }
      TlsStreamState::Open(..) => f.write_fmt(format_args!(
        "TlsStream {{ Open, handshake: {:?} }}",
        self.handshake.handshake.lock().unwrap()
      )),
      TlsStreamState::Closed => f.write_str("TlsStream { Closed }"),
      TlsStreamState::ClosedError(err) => {
        f.write_fmt(format_args!("TlsStream {{ Closed, error: {:?} }}", err))
      }
    }
  }
}

/// The handshake results from a TLS connection.
#[derive(Clone, Debug)]
pub struct TlsHandshake {
  pub alpn: Option<Vec<u8>>,
  pub sni: Option<String>,
  /// For client-to-server connections, will always return true. For server-to-client connections, returns
  /// true if the client provided a valid certificate.
  pub has_peer_certificates: bool,
  /// The peer certificates from the TLS handshake, if available.
  pub peer_certificates:
    Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
}

impl TlsStream<TcpStream> {
  pub fn linger(&self) -> Result<Option<Duration>, io::Error> {
    match &self.state {
      TlsStreamState::Open(stm) => stm.underlying_stream().linger(),
      TlsStreamState::Handshaking {
        underlying: tcp, ..
      } => tcp.linger(),
      TlsStreamState::Closed | TlsStreamState::ClosedError(_) => {
        Err(std::io::ErrorKind::NotConnected.into())
      }
    }
  }

  pub fn set_linger(&self, dur: Option<Duration>) -> Result<(), io::Error> {
    match &self.state {
      TlsStreamState::Open(stm) => stm.underlying_stream().set_linger(dur),
      TlsStreamState::Handshaking {
        underlying: tcp, ..
      } => tcp.set_linger(dur),
      TlsStreamState::Closed | TlsStreamState::ClosedError(_) => {
        Err(std::io::ErrorKind::NotConnected.into())
      }
    }
  }

  /// Returns the peer address of this socket.
  pub fn peer_addr(&self) -> Result<std::net::SocketAddr, io::Error> {
    match &self.state {
      TlsStreamState::Open(stm) => stm.underlying_stream().peer_addr(),
      TlsStreamState::Handshaking {
        underlying: tcp, ..
      } => tcp.peer_addr(),
      TlsStreamState::Closed | TlsStreamState::ClosedError(_) => {
        Err(std::io::ErrorKind::NotConnected.into())
      }
    }
  }

  /// Returns the local address of this socket.
  pub fn local_addr(&self) -> Result<std::net::SocketAddr, io::Error> {
    match &self.state {
      TlsStreamState::Open(stm) => stm.underlying_stream().local_addr(),
      TlsStreamState::Handshaking {
        underlying: tcp, ..
      } => tcp.local_addr(),
      TlsStreamState::Closed | TlsStreamState::ClosedError(_) => {
        Err(std::io::ErrorKind::NotConnected.into())
      }
    }
  }
}

#[cfg(unix)]
impl TlsStream<tokio::net::UnixStream> {
  pub fn peer_addr(&self) -> Result<tokio::net::unix::SocketAddr, io::Error> {
    match &self.state {
      TlsStreamState::Open(stm) => stm.underlying_stream().peer_addr(),
      TlsStreamState::Handshaking {
        underlying: tcp, ..
      } => tcp.peer_addr(),
      TlsStreamState::Closed | TlsStreamState::ClosedError(_) => {
        Err(std::io::ErrorKind::NotConnected.into())
      }
    }
  }

  pub fn local_addr(&self) -> Result<tokio::net::unix::SocketAddr, io::Error> {
    match &self.state {
      TlsStreamState::Open(stm) => stm.underlying_stream().local_addr(),
      TlsStreamState::Handshaking {
        underlying: tcp, ..
      } => tcp.local_addr(),
      TlsStreamState::Closed | TlsStreamState::ClosedError(_) => {
        Err(std::io::ErrorKind::NotConnected.into())
      }
    }
  }
}

impl<S: UnderlyingStream + 'static> TlsStream<S> {
  fn new(
    tcp: S,
    mut tls: Connection,
    buffer_size: Option<NonZeroUsize>,
    test_options: TestOptions,
  ) -> Self {
    tls.set_buffer_limit(buffer_size.map(|s| s.get()));
    let handshake = Arc::new(HandshakeWatch::default());
    let wakers = DeferredWakers::default();
    let wakers_clone = wakers.clone();
    let tcp = Arc::new(tcp);
    let tcp_handshake = tcp.clone();

    let handshake_send = handshake.clone();
    let handle = spawn(async move {
      let res =
        send_handshake(tcp_handshake, Ok(tls), test_options, handshake_send)
          .await;

      // We may have read/writes blocked on the handshake, so wake them all up
      wakers_clone.wake();

      res
    });

    Self {
      state: TlsStreamState::Handshaking {
        handle,
        wakers,
        write_buf: vec![],
        underlying: tcp,
      },
      handshake,
      buffer_size,
    }
  }

  async fn accept(
    mut acceptor: Acceptor,
    tcp_handshake: &S,
    server_config_provider: ServerConfigProvider,
  ) -> Result<ServerConnection, io::Error> {
    loop {
      tcp_handshake.readable().await?;
      // Stop if connection was closed by client
      if read_acceptor(tcp_handshake, &mut acceptor)? < 1 {
        return Err(io::ErrorKind::ConnectionReset.into());
      }

      let accepted = match acceptor.accept() {
        Ok(Some(accepted)) => accepted,
        Ok(None) => continue,
        Err((e, alert)) => {
          tcp_handshake.writable().await?;
          write_acceptor_alert(tcp_handshake, alert)?;
          return Err(rustls_to_io_error(e));
        }
      };

      let config = match server_config_provider(accepted.client_hello()).await {
        Ok(config) => config,
        Err(err) => {
          // This is a bad case. The provider was supposed to give us a config, but instead it failed.
          //
          // There's no easy way to reject an acceptor, and we only have an Arc for the stream so we can't close
          // it. Instead we send a fatal alert manually which is effectively going to close the stream.
          //
          // Wireshark packet decode:
          //     TLSv1.2 Record Layer: Alert (Level: Fatal, Description: Close Notify)
          //         Content Type: Alert (21)
          //         Version: TLS 1.2 (0x0303)
          //         Length: 2
          //         Alert Message
          //             Level: Fatal (2)
          //             Description: Close Notify (0)
          const FATAL_ALERT: &[u8] = b"\x15\x03\x03\x00\x02\x02\x00";
          for c in FATAL_ALERT {
            tcp_handshake.writable().await?;
            tcp_handshake.try_write(&[*c])?;
          }
          return Err(err);
        }
      };
      match accepted.into_connection(config) {
        Ok(tls) => {
          return Ok(tls);
        }
        Err((e, alert)) => {
          tcp_handshake.writable().await?;
          write_acceptor_alert(tcp_handshake, alert)?;
          return Err(rustls_to_io_error(e));
        }
      }
    }
  }

  fn new_server_acceptor(
    acceptor: Acceptor,
    tcp: S,
    server_config_provider: ServerConfigProvider,
    buffer_size: Option<NonZeroUsize>,
    test_options: TestOptions,
  ) -> Self {
    let handshake = Arc::new(HandshakeWatch::default());
    let wakers = DeferredWakers::default();
    let wakers_clone = wakers.clone();
    let tcp = Arc::new(tcp);
    let tcp_handshake = tcp.clone();

    let handshake_send = handshake.clone();

    let handle = spawn(async move {
      let tls =
        Self::accept(acceptor, &tcp_handshake, server_config_provider).await;
      let res = send_handshake(
        tcp_handshake,
        tls.map(rustls::Connection::Server),
        test_options,
        handshake_send,
      )
      .await;

      // We may have read/writes blocked on the handshake, so wake them all up
      wakers_clone.wake();

      res
    });

    Self {
      state: TlsStreamState::Handshaking {
        handle,
        wakers,
        write_buf: vec![],
        underlying: tcp,
      },
      handshake,
      buffer_size,
    }
  }

  pub fn new_client_side(
    tcp: S,
    tls: ClientConnection,
    buffer_size: Option<NonZeroUsize>,
  ) -> Self {
    Self::new(
      tcp,
      Connection::Client(tls),
      buffer_size,
      TestOptions::default(),
    )
  }

  #[cfg(test)]
  pub(crate) fn new_client_side_test_options(
    tcp: S,
    tls_config: Arc<rustls::ClientConfig>,
    server_name: rustls::pki_types::ServerName<'_>,
    buffer_size: Option<NonZeroUsize>,
    test_options: TestOptions,
  ) -> Self {
    let tls =
      ClientConnection::new(tls_config, server_name.to_owned()).unwrap();
    Self::new(tcp, Connection::Client(tls), buffer_size, test_options)
  }

  pub fn new_client_side_from(
    tcp: S,
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
    tcp: S,
    tls_config: Arc<ServerConfig>,
    buffer_size: Option<NonZeroUsize>,
    test_options: TestOptions,
  ) -> Self {
    let tls = ServerConnection::new(tls_config).unwrap();
    Self::new(tcp, Connection::Server(tls), buffer_size, test_options)
  }

  pub fn new_server_side(
    tcp: S,
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

  /// Create a server-side TLS connection that provides the [`ServerConfig`] dynamically
  /// based on the [`ClientHello`] message. This may be used to provide a different server
  /// certificate or ALPN configuration depending on the requested hostname.
  pub fn new_server_side_acceptor(
    tcp: S,
    server_config_provider: ServerConfigProvider,
    buffer_size: Option<NonZeroUsize>,
  ) -> Self {
    Self::new_server_acceptor(
      Acceptor::default(),
      tcp,
      server_config_provider,
      buffer_size,
      TestOptions::default(),
    )
  }

  /// Create a server-side TLS connection that provides the [`ServerConfig`] dynamically
  /// based on the [`ClientHello`] message. This may be used to provide a different server
  /// certificate or ALPN configuration depending on the requested hostname.
  ///
  /// This allows the caller to provide an [`Acceptor`] which may be non-default in some
  /// way, perhaps stuffed with prefix bytes or a full handshake to emulate.
  pub fn new_server_side_from_acceptor(
    acceptor: Acceptor,
    tcp: S,
    server_config_provider: ServerConfigProvider,
    buffer_size: Option<NonZeroUsize>,
  ) -> Self {
    Self::new_server_acceptor(
      acceptor,
      tcp,
      server_config_provider,
      buffer_size,
      TestOptions::default(),
    )
  }

  pub fn new_server_side_from(
    tcp: S,
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
  pub fn try_into_inner(mut self) -> Result<(S, Connection), Self> {
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

  pub fn into_split(self) -> (TlsStreamRead<S>, TlsStreamWrite<S>) {
    let handshake1 = self.handshake.clone();
    let handshake2 = self.handshake.clone();
    let tcp = match &self.state {
      TlsStreamState::Handshaking {
        underlying: tcp, ..
      } => Some(tcp.clone()),
      TlsStreamState::Open(conn) => Some(conn.underlying_stream().clone()),
      _ => None,
    };
    let (r, w) = tokio::io::split(self);
    let read = TlsStreamRead {
      r,
      handshake: handshake1,
      tcp: tcp.clone(),
    };
    let write = TlsStreamWrite {
      w,
      handshake: handshake2,
      tcp,
    };
    (read, write)
  }

  /// If the stream is open, returns the underlying rustls connection.
  pub fn connection(&self) -> Option<&rustls::Connection> {
    match &self.state {
      TlsStreamState::Open(stm) => Some(stm.connection()),
      _ => None,
    }
  }

  pub async fn into_inner(mut self) -> io::Result<(S, Connection)> {
    poll_fn(|cx| self.poll_pending_handshake(cx)).await?;
    match std::mem::replace(&mut self.state, TlsStreamState::Closed) {
      TlsStreamState::Open(stm) => Ok(stm.into_inner()),
      TlsStreamState::Closed => Err(ErrorKind::NotConnected.into()),
      TlsStreamState::ClosedError(err) => Err(err),
      TlsStreamState::Handshaking { .. } => unreachable!(),
    }
  }

  pub fn poll_handshake(
    &mut self,
    cx: &mut Context,
  ) -> Poll<io::Result<TlsHandshake>> {
    // Transition to the open state if necessary
    ready!(self.poll_pending_handshake(cx)?);

    // TODO(mmastrac): Handshake shouldn't need to be cloned
    match &*self.handshake.handshake.lock().unwrap() {
      None => {
        // Register both wakers just in case we get split
        self.handshake.rx_waker.register(cx.waker());
        self.handshake.tx_waker.register(cx.waker());
        Poll::Pending
      }
      Some(handshake) => Poll::Ready(clone_result(handshake)),
    }
  }

  pub async fn handshake(&mut self) -> io::Result<TlsHandshake> {
    poll_fn(|cx| self.poll_handshake(cx)).await
  }

  /// Try to get the handshake, if one exists.
  pub fn try_handshake(&self) -> io::Result<Option<TlsHandshake>> {
    match &*self.handshake.handshake.lock().unwrap() {
      None => Ok(None),
      Some(r) => clone_result(r).map(Some),
    }
  }

  fn finalize_handshake(
    &mut self,
    join_result: Result<io::Result<HandshakeResult<S>>, JoinError>,
  ) -> io::Result<()> {
    trace!("finalize handshake");
    match std::mem::replace(&mut self.state, TlsStreamState::Closed) {
      TlsStreamState::Handshaking {
        wakers,
        write_buf: buf,
        ..
      } => {
        trace!("join={join_result:?}");
        match join_result {
          Err(err) => {
            // We polled the handle, so we need to update the state to something
            self.state = TlsStreamState::ClosedError(ErrorKind::Other.into());
            if err.is_panic() {
              // Resume the panic on the main task
              std::panic::resume_unwind(err.into_panic());
            } else {
              unreachable!("Task should not have been cancelled");
            }
          }
          Ok(Err(err)) => {
            self.state = TlsStreamState::ClosedError(clone_error(&err));
            Err(err)
          }
          Ok(Ok(result)) => {
            // TODO(mmastrac): if we split ConnectionStream we can remove this Arc and use reclaim2
            let (tcp, tls) = result.into_inner();
            let mut stm = ConnectionStream::new(tcp, tls);
            trace!("hs buf={}", buf.len());
            // We need to save all the data we wrote before the connection. The stream has an internal buffer
            // that matches our buffer, so it can accept it all.
            stm.write_buf_fully(&buf);

            wakers.wake();
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
      self.state = TlsStreamState::ClosedError(err);
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
      TlsStreamState::ClosedError(err) => Poll::Ready(Err(clone_error(err))),
    }
  }

  pub async fn close(mut self) -> io::Result<()> {
    trace!("closing {self:?}");
    let state = std::mem::replace(&mut self.state, TlsStreamState::Closed);
    match state {
      TlsStreamState::Handshaking {
        handle,
        wakers,
        write_buf: buf,
        ..
      } => {
        wakers.wake();
        match handle.await {
          Ok(Ok(result)) => {
            // TODO(mmastrac): if we split ConnectionStream we can remove this Arc and use reclaim2
            let (tcp, tls) = result.into_inner();
            let mut stm = ConnectionStream::new(tcp, tls);
            poll_fn(|cx| stm.poll_write(cx, &buf)).await?;
            poll_fn(|cx| stm.poll_shutdown(cx)).await?;
            nonblocking_tcp_drop(stm);
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
        nonblocking_tcp_drop(stm);
      }
      TlsStreamState::Closed | TlsStreamState::ClosedError(_) => {
        // Nothing
      }
    }

    Ok(())
  }
}

impl<S: UnderlyingStream> TlsStream<S> {
  /// If the stream is open or handshaking, returns the underlying TCP stream.
  pub fn underlying_stream(&self) -> Option<&S> {
    match &self.state {
      TlsStreamState::Open(stm) => Some(stm.underlying_stream()),
      TlsStreamState::Handshaking {
        underlying: tcp, ..
      } => Some(tcp),
      _ => None,
    }
  }
}

async fn send_handshake<S: UnderlyingStream>(
  tcp: Arc<S>,
  tls: Result<Connection, io::Error>,
  test_options: TestOptions,
  handshake: Arc<HandshakeWatch>,
) -> Result<HandshakeResult<S>, io::Error> {
  let tls = match tls {
    Ok(tls) => tls,
    Err(err) => {
      *handshake.handshake.lock().unwrap() = Some(Err(clone_error(&err)));
      handshake.rx_waker.wake();
      handshake.tx_waker.wake();
      return Err(err);
    }
  };

  #[cfg(test)]
  if test_options.delay_handshake {
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
  }
  let res = handshake_task(tcp, tls, test_options).await;
  match &res {
    Ok(res) => {
      let peer_certificates = res
        .1
        .peer_certificates()
        .map(|certs| certs.iter().map(|cert| cert.clone()).collect());
      let has_peer_certificates = peer_certificates
        .as_ref()
        .map(|c: &Vec<rustls::pki_types::CertificateDer<'static>>| {
          !c.is_empty()
        })
        .unwrap_or_default();
      let alpn = res.1.alpn_protocol().map(|v| v.to_owned());
      let sni = match &res.1 {
        Connection::Server(server) => {
          server.server_name().map(|s| s.to_owned())
        }
        _ => None,
      };
      *handshake.handshake.lock().unwrap() = Some(Ok(TlsHandshake {
        alpn,
        sni,
        has_peer_certificates,
        peer_certificates,
      }));
    }
    Err(err) => {
      *handshake.handshake.lock().unwrap() = Some(Err(clone_error(err)));
    }
  }
  handshake.rx_waker.wake();
  handshake.tx_waker.wake();
  res
}

/// TLS 1.3 may yield a state where the client has sent a large stream of data and closed
/// the connection before receiving anything from the server. The server may attempt to
/// send the final part of its handshake to the client's closed socket, which yields a TCP
/// reset and then causes the server to throw away its received buffer. This holds a TCP
/// socket open for a shortly extended period of time if we have a TLS 1.3 client.
fn nonblocking_tcp_drop<S: UnderlyingStream>(stm: ConnectionStream<S>) {
  // TODO(mmastrac) A better fix would be detecting that the server has sent at least one post-handshake packet,
  // which would indicate that it's safe to close at this point.
  let (inner, tls) = stm.into_inner();
  if matches!(tls, Connection::Client(_))
    && tls.protocol_version() == Some(TLS13.version)
  {
    if let Ok(tcp) = inner.downcast::<TcpStream>() {
      if let Ok(tcp) = tcp.into_std() {
        spawn_blocking(move || {
          trace!("in drop tcp task");
          sleep(Duration::from_millis(100));
          drop(tcp);
          trace!("done drop tcp task");
        });
      }
    }
  }
}

impl<S: UnderlyingStream> AsyncRead for TlsStream<S> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    loop {
      break match &mut self.state {
        TlsStreamState::Handshaking { handle, wakers, .. } => {
          // If the handshake completed, we want to finalize it and then continue
          if handle.is_finished() {
            // This may return Pending if we've exhausted the co-op budget
            let res = ready!(handle.poll_unpin(cx));
            self.finalize_handshake(res)?;
            continue;
          }

          // Handshake is still blocking us
          wakers.set_read_waker(cx.waker());

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
        TlsStreamState::ClosedError(err) => Poll::Ready(Err(clone_error(err))),
      };
    }
  }
}

impl<S: UnderlyingStream> AsyncWrite for TlsStream<S> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    // NOTE: Changes to this method may need to be reflected in `poll_write_vectored`
    let buffer_size = self.buffer_size;
    loop {
      break match &mut self.state {
        TlsStreamState::Handshaking {
          handle,
          wakers,
          write_buf,
          ..
        } => {
          // If the handshake completed, we want to finalize it and then continue
          if handle.is_finished() {
            // This may return Pending if we've exhausted the co-op budget
            let res = ready!(handle.poll_unpin(cx));
            self.finalize_handshake(res)?;
            continue;
          }

          if let Some(buffer_size) = buffer_size {
            let remaining = buffer_size.get() - write_buf.len();
            if remaining == 0 {
              // No room to write, so store the waker for whenever the handshake is done
              wakers.set_write_waker(cx.waker());
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
        TlsStreamState::ClosedError(err) => Poll::Ready(Err(clone_error(err))),
      };
    }
  }

  fn poll_write_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[std::io::IoSlice<'_>],
  ) -> Poll<Result<usize, io::Error>> {
    // NOTE: Changes to this method may need to be reflected in `poll_write`
    let buffer_size = self.buffer_size;
    loop {
      break match &mut self.state {
        TlsStreamState::Handshaking {
          handle,
          wakers,
          write_buf,
          ..
        } => {
          // If the handshake completed, we want to finalize it and then continue
          if handle.is_finished() {
            // This may return Pending if we've exhausted the co-op budget
            let res = ready!(handle.poll_unpin(cx));
            self.finalize_handshake(res)?;
            continue;
          }
          if let Some(buffer_size) = buffer_size {
            let mut remaining = buffer_size.get() - write_buf.len();
            if remaining == 0 {
              // No room to write, so store the waker for whenever the handshake is done
              wakers.set_write_waker(cx.waker());
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
        TlsStreamState::ClosedError(err) => Poll::Ready(Err(clone_error(err))),
      };
    }
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    loop {
      break match &mut self.state {
        TlsStreamState::Handshaking { wakers, handle, .. } => {
          // If the handshake completed, we want to finalize it and then continue
          if handle.is_finished() {
            // This may return Pending if we've exhausted the co-op budget
            let res = ready!(handle.poll_unpin(cx));
            self.finalize_handshake(res)?;
            continue;
          }

          wakers.set_write_waker(cx.waker());
          Poll::Pending
        }
        TlsStreamState::Open(stm) => stm.poll_flush(cx),
        TlsStreamState::Closed => {
          Poll::Ready(Err(ErrorKind::NotConnected.into()))
        }
        TlsStreamState::ClosedError(err) => Poll::Ready(Err(clone_error(err))),
      };
    }
  }

  fn is_write_vectored(&self) -> bool {
    // While rustls supports vectored writes, they act more like buffered writes so
    // we should prefer upstream producers to pre-aggregate when possible.
    false
  }

  fn poll_shutdown(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), io::Error>> {
    self.poll_shutdown_or_abort(cx, false)
  }
}

impl<S: UnderlyingStream> Drop for TlsStream<S> {
  fn drop(&mut self) {
    trace!("dropping {self:?}");
    let state = std::mem::replace(&mut self.state, TlsStreamState::Closed);
    match state {
      TlsStreamState::Handshaking {
        handle,
        write_buf,
        underlying: tcp,
        ..
      } => {
        spawn(async move {
          trace!("in drop task");
          match handle.await {
            Ok(Ok(result)) => {
              drop(tcp);
              // TODO(mmastrac): if we split ConnectionStream we can remove this Arc and use reclaim2
              let (tcp, tls) = result.into_inner();
              let mut stm = ConnectionStream::new(tcp, tls);
              stm.write_buf_fully(&write_buf);
              let res = poll_fn(|cx| stm.poll_shutdown(cx)).await;
              trace!("shutdown handshake {:?}", res);
              nonblocking_tcp_drop(stm);
            }
            x @ Err(_) => {
              trace!("{x:?}");
            }
            x @ Ok(Err(_)) => {
              trace!("{x:?}");
            }
          }
          trace!("done drop task");
        });
      }
      TlsStreamState::Open(mut stm) => {
        spawn(async move {
          trace!("in drop task");
          let res = poll_fn(|cx| stm.poll_shutdown(cx)).await;
          trace!("shutdown open {:?}", res);
          nonblocking_tcp_drop(stm);
          trace!("done drop task");
        });
      }
      TlsStreamState::Closed | TlsStreamState::ClosedError(_) => {
        // Nothing
      }
    }
  }
}

/// An `async` read half of stream that wraps a `rustls` connection and a TCP socket.
#[derive(AsyncRead)]
pub struct TlsStreamRead<S: UnderlyingStream> {
  #[read]
  r: tokio::io::ReadHalf<TlsStream<S>>,
  handshake: Arc<HandshakeWatch>,
  tcp: Option<Arc<S>>,
}

impl TlsStreamRead<TcpStream> {
  /// Returns the peer address of this socket.
  pub fn peer_addr(&self) -> Result<std::net::SocketAddr, io::Error> {
    let Some(tcp) = &self.tcp else {
      return Err(std::io::ErrorKind::NotConnected.into());
    };
    tcp.peer_addr()
  }

  /// Returns the local address of this socket.
  pub fn local_addr(&self) -> Result<std::net::SocketAddr, io::Error> {
    let Some(tcp) = &self.tcp else {
      return Err(std::io::ErrorKind::NotConnected.into());
    };
    tcp.local_addr()
  }
}

impl<S: UnderlyingStream> TlsStreamRead<S> {
  /// Reunites with a previously split `TlsStreamWrite`.
  pub fn unsplit(self, other: TlsStreamWrite<S>) -> TlsStream<S> {
    self.r.unsplit(other.w)
  }

  pub fn poll_handshake(
    &mut self,
    cx: &mut Context,
  ) -> Poll<io::Result<TlsHandshake>> {
    // TODO(mmastrac): Handshake shouldn't need to be cloned
    match &*self.handshake.handshake.lock().unwrap() {
      None => {
        self.handshake.rx_waker.register(cx.waker());
        Poll::Pending
      }
      Some(handshake) => Poll::Ready(clone_result(handshake)),
    }
  }

  pub async fn handshake(&mut self) -> io::Result<TlsHandshake> {
    poll_fn(|cx| self.poll_handshake(cx)).await
  }

  /// Try to get the handshake, if one exists.
  pub fn try_handshake(&self) -> io::Result<Option<TlsHandshake>> {
    match &*self.handshake.handshake.lock().unwrap() {
      None => Ok(None),
      Some(r) => clone_result(r).map(Some),
    }
  }
}

/// An `async` write half of stream that wraps a `rustls` connection and a TCP socket.
#[derive(AsyncWrite)]
pub struct TlsStreamWrite<S: UnderlyingStream> {
  #[write]
  w: tokio::io::WriteHalf<TlsStream<S>>,
  handshake: Arc<HandshakeWatch>,
  tcp: Option<Arc<S>>,
}

impl TlsStreamWrite<TcpStream> {
  /// Returns the peer address of this socket.
  pub fn peer_addr(&self) -> Result<std::net::SocketAddr, io::Error> {
    let Some(tcp) = &self.tcp else {
      return Err(std::io::ErrorKind::NotConnected.into());
    };
    tcp.peer_addr()
  }

  /// Returns the local address of this socket.
  pub fn local_addr(&self) -> Result<std::net::SocketAddr, io::Error> {
    let Some(tcp) = &self.tcp else {
      return Err(std::io::ErrorKind::NotConnected.into());
    };
    tcp.local_addr()
  }
}

impl<S: UnderlyingStream> TlsStreamWrite<S> {
  pub fn poll_handshake(
    &mut self,
    cx: &mut Context,
  ) -> Poll<io::Result<TlsHandshake>> {
    // TODO(mmastrac): Handshake shouldn't need to be cloned
    match &*self.handshake.handshake.lock().unwrap() {
      None => {
        self.handshake.tx_waker.register(cx.waker());
        Poll::Pending
      }
      Some(handshake) => Poll::Ready(clone_result(handshake)),
    }
  }

  pub async fn handshake(&mut self) -> io::Result<TlsHandshake> {
    poll_fn(|cx| self.poll_handshake(cx)).await
  }

  /// Try to get the handshake, if one exists.
  pub fn try_handshake(&self) -> io::Result<Option<TlsHandshake>> {
    match &*self.handshake.handshake.lock().unwrap() {
      None => Ok(None),
      Some(r) => clone_result(r).map(Some),
    }
  }
}

#[cfg(test)]
pub(super) mod tests {
  use super::*;
  use crate::tests::certificate;
  use crate::tests::expect_io_error;
  use crate::tests::private_key;
  use crate::tests::UnsafeVerifier;
  use futures::stream::FuturesUnordered;
  use futures::FutureExt;
  use futures::StreamExt;
  use rstest::rstest;
  use rustls::version::TLS12;
  use rustls::ClientConfig;
  use rustls::SupportedProtocolVersion;
  use std::io::ErrorKind;
  use std::io::IoSlice;
  use std::net::Ipv4Addr;
  use std::net::SocketAddr;
  use std::net::SocketAddrV4;
  use std::time::Duration;
  use tokio::io::AsyncReadExt;
  use tokio::io::AsyncWriteExt;
  use tokio::net::TcpListener;
  use tokio::net::TcpSocket;
  use tokio::spawn;
  use tokio::sync::Barrier;

  type TestResult = Result<(), std::io::Error>;

  type TlsStream = super::TlsStream<TcpStream>;

  fn server_config(alpn: &[&str]) -> ServerConfig {
    let mut config = ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(vec![certificate()], private_key())
      .expect("Failed to build server config");
    config.alpn_protocols =
      alpn.iter().map(|v| v.as_bytes().to_owned()).collect();
    config
  }

  fn server_config_protocol(
    protocol: &'static SupportedProtocolVersion,
  ) -> ServerConfig {
    let config = ServerConfig::builder_with_protocol_versions(&[protocol])
      .with_no_client_auth()
      .with_single_cert(vec![certificate()], private_key())
      .expect("Failed to build server config");
    config
  }

  fn client_config(alpn: &[&str]) -> ClientConfig {
    let mut config = ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(UnsafeVerifier {}))
      .with_no_client_auth();
    config.alpn_protocols =
      alpn.iter().map(|v| v.as_bytes().to_owned()).collect();
    config.enable_sni = true;
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

  pub async fn tls_pair_protocol(
    buffer_size: Option<NonZeroUsize>,
    protocol: &'static SupportedProtocolVersion,
  ) -> (TlsStream, TlsStream) {
    let (server, client) = tcp_pair().await;
    let server = TlsStream::new_server_side(
      server,
      server_config_protocol(protocol).into(),
      None,
    );
    let client = TlsStream::new_client_side_test_options(
      client,
      client_config(&[]).into(),
      "example.com".try_into().unwrap(),
      buffer_size,
      TestOptions::default(),
    );

    (server, client)
  }

  pub async fn tls_pair_buffer_size(
    buffer_size: Option<NonZeroUsize>,
  ) -> (TlsStream, TlsStream) {
    let (server, client) = tcp_pair().await;
    let server =
      TlsStream::new_server_side(server, server_config(&[]).into(), None);
    let client = TlsStream::new_client_side_test_options(
      client,
      client_config(&[]).into(),
      "example.com".try_into().unwrap(),
      buffer_size,
      TestOptions::default(),
    );

    (server, client)
  }

  async fn tls_with_tcp_server(
    delay_handshake: bool,
  ) -> (TcpStream, TlsStream) {
    let (server, client) = tcp_pair().await;
    let client_test_options = TestOptions {
      delay_handshake,
      ..Default::default()
    };
    let client = TlsStream::new_client_side_test_options(
      client,
      client_config(&[]).into(),
      "example.com".try_into().unwrap(),
      None,
      client_test_options,
    );
    (server, client)
  }

  async fn tls_pair_slow_handshake(
    delay_handshake: bool,
    slow_server: bool,
    slow_client: bool,
    buffer: bool,
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
    let buffer_size = if buffer {
      NonZeroUsize::new(1024)
    } else {
      None
    };

    let server = TlsStream::new_server_side_test_options(
      server,
      server_config(&[]).into(),
      buffer_size,
      server_test_options,
    );
    let client = TlsStream::new_client_side_test_options(
      client,
      client_config(&[]).into(),
      "example.com".try_into().unwrap(),
      buffer_size,
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
    let client = TlsStream::new_client_side_test_options(
      client,
      client_config(client_alpn).into(),
      "example.com".try_into().unwrap(),
      client_buffer_size,
      TestOptions::default(),
    );

    (server, client)
  }

  async fn make_config(
    alpn: Result<&'static [&'static str], &'static str>,
  ) -> Result<Arc<ServerConfig>, io::Error> {
    Ok(
      server_config(
        alpn.map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
      )
      .into(),
    )
  }

  async fn tls_pair_alpn_acceptor(
    server_alpn: fn(
      ClientHello,
    ) -> Result<&'static [&'static str], &'static str>,
    server_buffer_size: Option<NonZeroUsize>,
    client_alpn: &[&str],
    client_buffer_size: Option<NonZeroUsize>,
  ) -> (TlsStream, TlsStream) {
    let (server, client) = tcp_pair().await;
    let server = TlsStream::new_server_side_acceptor(
      server,
      Arc::new(move |client_hello| {
        Box::pin(make_config(server_alpn(client_hello)))
      }),
      server_buffer_size,
    );
    let client = TlsStream::new_client_side_test_options(
      client,
      client_config(client_alpn).into(),
      "example.com".try_into().unwrap(),
      client_buffer_size,
      TestOptions::default(),
    );

    (server, client)
  }

  async fn tls_pair_alpn_from_acceptor(
    server_alpn: fn(
      ClientHello,
    ) -> Result<&'static [&'static str], &'static str>,
    server_buffer_size: Option<NonZeroUsize>,
    client_alpn: &[&str],
    client_buffer_size: Option<NonZeroUsize>,
  ) -> (TlsStream, TlsStream) {
    let (mut server, client) = tcp_pair().await;

    // Create the client first because we need the ClientHello. This will
    // boot the client's handshake task and write to the socket.
    let client = TlsStream::new_client_side_test_options(
      client,
      client_config(client_alpn).into(),
      "example.com".try_into().unwrap(),
      client_buffer_size,
      TestOptions::default(),
    );

    // Read 8 bytes from the start of the server connection and then
    // feed them to an Acceptor. Pass that acceptor when we create the
    // TlsStream which will populate the rest of the ClientHello and
    // properly handshake.
    let mut prefix = [0; 8];
    server
      .read_exact(&mut prefix)
      .await
      .expect("Failed to read prefix");
    let mut acceptor = Acceptor::default();
    assert_eq!(
      acceptor.read_tls(&mut prefix.as_slice()).unwrap(),
      prefix.len()
    );

    let server = TlsStream::new_server_side_from_acceptor(
      acceptor,
      server,
      Arc::new(move |client_hello| {
        Box::pin(make_config(server_alpn(client_hello)))
      }),
      server_buffer_size,
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

  async fn expect_eof_read(stm: &mut (impl AsyncReadExt + Unpin)) {
    let mut buf = [0_u8; 1];
    let e = stm.read(&mut buf).await.expect("Expected no error");
    assert_eq!(e, 0, "expected eof");
  }

  async fn expect_io_error_read(
    stm: &mut (impl AsyncReadExt + Unpin),
    kind: io::ErrorKind,
  ) {
    let mut buf = [0_u8; 1];
    let e = stm.read(&mut buf).await.expect_err("Expected error");
    assert_eq!(e.kind(), kind);
  }

  /// Test that automatic state transition works: send and receive work as expected without waiting
  /// for the handshake
  #[rstest]
  #[tokio::test]
  async fn test_client_server(
    #[values(true, false)] server_slow: bool,
    #[values(true, false)] client_slow: bool,
    #[values(true, false)] buffer: bool,
  ) -> TestResult {
    let (mut server, mut client) =
      tls_pair_slow_handshake(false, server_slow, client_slow, buffer).await;
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

  /// Test that a flush before a handshake completes works.
  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_flush_before_handshake() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    server.write_all(b"hello?").await.unwrap();
    server.flush().await.unwrap();
    let mut buf = [0; 6];
    assert_eq!(6, client.read_exact(&mut buf).await.unwrap());
    Ok(())
  }

  #[rstest]
  #[tokio::test(flavor = "multi_thread")]
  #[ntest::timeout(60000)]
  async fn test_read_with_buffered_write(
    #[values(true, false)] delay_handshake: bool,
    #[values(true, false)] slow_server: bool,
    #[values(true, false)] slow_client: bool,
    #[values(true, false)] buffer: bool,
  ) -> TestResult {
    let (mut server, mut client) = tls_pair_slow_handshake(
      delay_handshake,
      slow_server,
      slow_client,
      buffer,
    )
    .await;

    let a = tokio::task::spawn(async move {
      server.read_u8().await.unwrap();
      server.write_u8(1).await.unwrap();
    });

    let b = tokio::task::spawn(async move {
      let buf = [0; 1024];
      client.write_all(&buf).await.unwrap();
      client.read_u8().await.unwrap();
    });

    a.await.unwrap();
    b.await.unwrap();

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
      assert_eq!(handshake.sni, Some("example.com".into()));
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

  /// Test that the handshake works, and we get the correct ALPN negotiated values.
  #[rstest]
  #[case("a")]
  #[case("b")]
  #[case("c")]
  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_client_server_alpn_acceptor(
    #[case] alpn: &'static str,
    #[values(true, false)] use_from: bool,
  ) -> TestResult {
    let (mut server, mut client) = if use_from {
      tls_pair_alpn_from_acceptor(alpn_handler, None, &[alpn], None).await
    } else {
      tls_pair_alpn_acceptor(alpn_handler, None, &[alpn], None).await
    };
    let a = spawn(async move {
      if alpn == "c" {
        server.handshake().await.expect_err("expected failure");
        return;
      }
      let handshake = server.handshake().await.unwrap();
      assert_eq!(handshake.alpn, Some(alpn.as_bytes().to_vec()));
      assert_eq!(handshake.sni, Some("example.com".into()));
      server.write_all(b"hello?").await.unwrap();
      let mut buf = [0; 6];
      server.read_exact(&mut buf).await.unwrap();
      assert_eq!(buf.as_slice(), b"hello!");
    });
    let b = spawn(async move {
      if alpn == "c" {
        client.handshake().await.expect_err("expected failure");
        return;
      }
      let handshake = client.handshake().await.unwrap();
      assert_eq!(handshake.alpn, Some(alpn.as_bytes().to_vec()));
      client.write_all(b"hello!").await.unwrap();
      let mut buf = [0; 6];
      client.read_exact(&mut buf).await.unwrap();
    });
    a.await?;
    b.await?;

    Ok(())
  }

  /// Test that the handshake fails, and we get the correct errors on both ends.
  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_client_server_alpn_mismatch() -> TestResult {
    let (mut server, mut client) =
      tls_pair_alpn(&["a"], None, &["b"], None).await;
    let a = spawn(async move {
      let e = server.handshake().await.expect_err("Expected a failure");
      assert_eq!(e.kind(), ErrorKind::InvalidData);
      assert_eq!(e.to_string(), "peer doesn't support any known protocol");
      let e = server.flush().await.expect_err("Expected a failure");
      assert_eq!(e.kind(), ErrorKind::InvalidData);
    });
    let b = spawn(async move {
      let e = client.handshake().await.expect_err("Expected a failure");
      assert_eq!(e.kind(), ErrorKind::InvalidData);
      assert_eq!(e.to_string(), "received fatal alert: NoApplicationProtocol");
      let e = client.flush().await.expect_err("Expected a failure");
      assert_eq!(e.kind(), ErrorKind::InvalidData);
    });
    a.await?;
    b.await?;

    Ok(())
  }

  /// Test that the handshake fails, and we get the correct errors on both ends.
  #[tokio::test]
  #[ntest::timeout(60000)]
  async fn test_client_server_raw_connection() -> TestResult {
    let (mut server, mut client) =
      tls_pair_alpn(&["a"], None, &["a"], None).await;

    assert!(server.connection().is_none());
    assert!(client.connection().is_none());

    server.handshake().await?;
    client.handshake().await?;

    assert!(server.connection().is_some());
    assert!(client.connection().is_some());

    Ok(())
  }

  #[tokio::test]
  async fn test_peer_and_local_addresses() {
    let (server, client) =
      tls_pair_slow_handshake(true, true, true, false).await;
    // Use a barrier to keep the client and server sockets alive until the end
    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = barrier.clone();
    let a = spawn(async move {
      loop {
        tokio::time::sleep(Duration::from_millis(10)).await;
        server.local_addr().unwrap();
        server.peer_addr().unwrap();
        if server.try_handshake().unwrap().is_some() {
          server.local_addr().unwrap();
          server.peer_addr().unwrap();
          break;
        }
      }
      barrier.wait().await;
    });
    let b = spawn(async move {
      loop {
        tokio::time::sleep(Duration::from_millis(10)).await;
        client.local_addr().unwrap();
        client.peer_addr().unwrap();
        if client.try_handshake().unwrap().is_some() {
          client.local_addr().unwrap();
          client.peer_addr().unwrap();
          break;
        }
      }
      barrier_clone.wait().await;
    });
    a.await.unwrap();
    b.await.unwrap();
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
      tls_pair_slow_handshake(false, server_slow, client_slow, false).await;
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
      tls_pair_slow_handshake(false, server_slow, client_slow, false).await;
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
      tls_pair_slow_handshake(false, server_slow, client_slow, false).await;
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
      tls_pair_slow_handshake(false, server_slow, client_slow, false).await;
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
      tls_pair_slow_handshake(false, server_slow, client_slow, false).await;
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
      tls_pair_slow_handshake(false, server_slow, client_slow, false).await;
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
      tls_pair_slow_handshake(false, server_slow, client_slow, false).await;
    drop(client);
    // The client will spawn a task to complete the handshake and then go away
    server.handshake().await?;
    // Can't read -- server shut down (but it was graceful)
    expect_eof_read(&mut server).await;
    Ok(())
  }

  #[tokio::test]
  async fn test_server_half_crash_before_handshake() -> TestResult {
    let (mut server, mut client) = tls_with_tcp_server(false).await;
    // This test occasionally shows up as ConnectionReset on Mac -- the delay ensures we wait long enough
    // for the handshake to settle.
    tokio::time::sleep(Duration::from_millis(100)).await;
    <TcpStream as AsyncWriteExt>::shutdown(&mut server).await?;

    let expected = ErrorKind::UnexpectedEof;

    expect_io_error(client.handshake().await, expected);
    // Can't read -- server shut down. Because this happened before the handshake, it's an unexpected EOF.
    expect_io_error_read(&mut client, expected).await;
    Ok(())
  }

  #[tokio::test]
  async fn test_server_crash_before_handshake() -> TestResult {
    let (mut server, mut client) = tls_with_tcp_server(false).await;
    <TcpStream as AsyncWriteExt>::shutdown(&mut server).await?;
    drop(server);

    let expected = ErrorKind::UnexpectedEof;

    expect_io_error(client.handshake().await, expected);
    // Can't read -- server shut down. Because this happened before the handshake, it's an unexpected EOF.
    expect_io_error_read(&mut client, expected).await;
    Ok(())
  }

  #[tokio::test]
  async fn test_server_crash_after_handshake() -> TestResult {
    let (server, mut client) = tls_pair_handshake().await;

    let (mut tcp, _tls) = server.into_inner().await.unwrap();
    <TcpStream as AsyncWriteExt>::shutdown(&mut tcp).await?;
    drop(tcp);

    // Can't read -- server shut down. This is an unexpected EOF.
    expect_io_error_read(&mut client, ErrorKind::UnexpectedEof).await;
    Ok(())
  }

  #[rstest]
  #[case(true)]
  #[case(false)]
  #[tokio::test]
  async fn large_transfer_no_buffer_limit_or_handshake(
    #[case] swap: bool,
  ) -> TestResult {
    const BUF_SIZE: usize = 64 * 1024;
    const BUF_COUNT: usize = 1024;

    let (server, client) = tls_pair().await;

    let (mut server, mut client) = if swap {
      (client, server)
    } else {
      (server, client)
    };

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

  #[rstest]
  #[case(true)]
  #[case(false)]
  #[tokio::test]
  async fn large_transfer_with_buffer_limit(#[case] swap: bool) -> TestResult {
    const BUF_SIZE: usize = 10 * 1024;
    const BUF_COUNT: usize = 1024;

    let (server, client) = tls_pair_handshake_buffer_size(
      BUF_SIZE.try_into().ok(),
      BUF_SIZE.try_into().ok(),
    )
    .await;

    let (mut server, mut client) = if swap {
      (client, server)
    } else {
      (server, client)
    };

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

  #[rstest]
  #[case(true, &TLS12)]
  #[case(false, &TLS12)]
  #[case(true, &TLS13)]
  #[case(false, &TLS13)]
  #[tokio::test]
  async fn large_transfer_with_aggressive_close_split(
    #[case] swap: bool,
    #[case] protocol: &'static SupportedProtocolVersion,
  ) -> TestResult {
    const BUF_SIZE: usize = 1024;
    const BUF_COUNT: usize = 1 * 1024;

    let (server, client) =
      tls_pair_protocol(NonZeroUsize::new(65536), protocol).await;
    let (server, client) = if swap {
      (client, server)
    } else {
      (server, client)
    };

    let a = spawn(async move {
      let (mut r, mut w) = server.into_split();
      let barrier = Arc::new(Barrier::new(2));
      let barrier2 = barrier.clone();
      let a = spawn(async move {
        // We want to register a read here to test whether the split read stomps over a write on
        // the other half.
        tokio::select! {
          x = r.read_u8() => { _ = x.expect_err("should have failed") },
          _ = barrier.wait() => {}
        };
        r
      });
      let b = spawn(async move {
        // Heap allocate a large buffer and send it
        let mut buf = vec![42; BUF_COUNT * BUF_SIZE];
        let mut buf: &mut [u8] = &mut buf;
        w.handshake().await.unwrap();
        while !buf.is_empty() {
          let n = w.write(&buf).await.unwrap();
          w.flush().await.unwrap();
          buf = &mut buf[n..];
          trace!("[TEST] wrote {n}");
        }
        w.shutdown().await.unwrap();
        barrier2.wait().await;
        w
      });

      let r = a.await.unwrap();
      let w = b.await.unwrap();
      // In TLS1.3, this aggressive close can cause the other side to lose its buffer
      // if the handshake is not fully completed because we send a TCP RST if we receive
      // anything further.
      r.unsplit(w).close().await.unwrap();
    });
    let b = spawn(async move {
      let (mut r, _w) = client.into_split();
      let mut buf = vec![0; BUF_SIZE];
      for i in 0..BUF_COUNT {
        let r = r.read_exact(&mut buf).await;
        if let Err(e) = &r {
          panic!("Failed to read after {i} of {BUF_COUNT} reads: {e:?}");
        };
        assert_eq!(BUF_SIZE, r.unwrap());
      }
      expect_eof_read(&mut r).await;
    });
    a.await?;
    b.await?;
    Ok(())
  }

  #[rstest]
  #[case(true)]
  #[case(false)]
  #[tokio::test(flavor = "current_thread")]
  async fn large_transfer_with_shutdown(#[case] swap: bool) -> TestResult {
    const BUF_SIZE: usize = 10 * 1024;
    const BUF_COUNT: usize = 1024;

    let (server, client) = tls_pair_handshake().await;
    let (mut server, mut client) = if swap {
      (client, server)
    } else {
      (server, client)
    };

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

  #[rstest]
  #[case(true)]
  #[case(false)]
  #[tokio::test(flavor = "current_thread")]
  #[ntest::timeout(60000)]
  async fn large_transfer_no_shutdown(#[case] swap: bool) -> TestResult {
    const BUF_SIZE: usize = 10 * 1024;
    const BUF_COUNT: usize = 1024;

    let (server, client) = tls_pair_handshake().await;
    let (mut server, mut client) = if swap {
      (client, server)
    } else {
      (server, client)
    };

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

  /// One byte read/write, don't check close.
  #[rstest]
  #[case(true, 1024, 1024, 1024)]
  #[case(false, 1024, 1024, 1024)]
  #[case(true, 1024, 16, 1024)]
  #[case(false, 1024, 16, 1024)]
  #[case(true, 1024, 10000, 1)]
  #[case(false, 1024, 10000, 1)]
  #[case(true, 32, 16, 16)]
  #[case(false, 32, 16, 16)]
  #[tokio::test]
  async fn vectored_stream_write(
    #[case] handshake_first: bool,
    #[case] expected: usize,
    #[case] first: usize,
    #[case] second: usize,
  ) -> TestResult {
    let (mut server, mut client) =
      tls_pair_buffer_size(Some(NonZeroUsize::try_from(1024).unwrap())).await;
    if handshake_first {
      server.handshake().await.unwrap();
      server.flush().await.unwrap();
      client.handshake().await.unwrap();
      client.flush().await.unwrap();
    }
    let n = client
      .write_vectored(&[
        IoSlice::new(&vec![1; first]),
        IoSlice::new(&vec![2; second]),
      ])
      .await
      .expect("failed to write");
    assert_eq!(n, expected);
    let mut buf = [0; 2048];
    // Note that we need to flush to make progress on writes!
    client.flush().await.expect("failed to flush");
    // We need the TCP stack to send all the writes -- in release mode this is sometimes too fast
    tokio::time::sleep(Duration::from_millis(1)).await;
    let n = server.read(&mut buf).await.expect("failed to read");
    assert_eq!(n, expected);
    Ok(())
  }

  /// Test that the peer_certificates are not available before handshake.
  #[tokio::test]
  async fn test_split_peer_certificates_before_handshake() -> TestResult {
    let (server, client) = tls_pair().await;

    let (server_read, server_write) = server.into_split();
    let (client_read, client_write) = client.into_split();

    // Test that handshake returns None before completion
    assert!(
      server_read.try_handshake()?.is_none(),
      "Server handshake should be None before completion"
    );
    assert!(
      server_write.try_handshake()?.is_none(),
      "Server handshake should be None before completion"
    );
    assert!(
      client_read.try_handshake()?.is_none(),
      "Client handshake should be None before completion"
    );
    assert!(
      client_write.try_handshake()?.is_none(),
      "Client handshake should be None before completion"
    );

    Ok(())
  }

  /// Test that the peer_certificates are available via handshake after completion.
  #[tokio::test]
  async fn test_split_peer_certificates_access() -> TestResult {
    let (server, client) = tls_pair_handshake().await;

    let (server_read, server_write) = server.into_split();
    let (client_read, client_write) = client.into_split();

    // Test that peer_certificates are available via handshake after completion
    let server_read_handshake = server_read.try_handshake()?.unwrap();
    let server_write_handshake = server_write.try_handshake()?.unwrap();
    let client_read_handshake = client_read.try_handshake()?.unwrap();
    let client_write_handshake = client_write.try_handshake()?.unwrap();

    // Both halves should return the same peer certificates via handshake
    assert_eq!(
      server_read_handshake.peer_certificates.is_some(),
      server_write_handshake.peer_certificates.is_some()
    );
    assert_eq!(
      client_read_handshake.peer_certificates.is_some(),
      client_write_handshake.peer_certificates.is_some()
    );

    if let (Some(read_certs), Some(write_certs)) = (
      &server_read_handshake.peer_certificates,
      &server_write_handshake.peer_certificates,
    ) {
      assert_eq!(read_certs.len(), write_certs.len());
    }

    if let (Some(read_certs), Some(write_certs)) = (
      &client_read_handshake.peer_certificates,
      &client_write_handshake.peer_certificates,
    ) {
      assert_eq!(read_certs.len(), write_certs.len());
    }

    Ok(())
  }
}
