// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

use futures::ready;
use futures::task::Context;
use futures::task::Poll;

use io::Error;
use io::Read;
use io::Write;
use rustls::Connection;
use std::convert::From;
use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Flow {
  Handshake,
  Read,
  Write,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum State {
  StreamOpen,
  StreamClosed,
  TlsClosing,
  TlsClosed,
  TcpClosed,
}

struct ImplementReadTrait<'a, T>(&'a mut T);

impl Read for ImplementReadTrait<'_, TcpStream> {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    self.0.try_read(buf)
  }
}

struct ImplementWriteTrait<'a, T>(&'a mut T);

impl Write for ImplementWriteTrait<'_, TcpStream> {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    match self.0.try_write(buf) {
      Ok(n) => Ok(n),
      Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(0),
      Err(err) => Err(err),
    }
  }

  fn flush(&mut self) -> io::Result<()> {
    Ok(())
  }
}

pub struct TlsStreamInner {
  pub(crate) tls: Connection,
  pub(crate) tcp: TcpStream,
  pub(crate) rd_state: State,
  pub(crate) wr_state: State,
}

impl TlsStreamInner {
  pub(crate) fn poll_io(&mut self, cx: &mut Context<'_>, flow: Flow) -> Poll<io::Result<()>> {
    loop {
      let wr_ready = loop {
        match self.wr_state {
          _ if self.tls.is_handshaking() && !self.tls.wants_write() => {
            break true;
          }
          _ if self.tls.is_handshaking() => {}
          State::StreamOpen if !self.tls.wants_write() => break true,
          State::StreamClosed => {
            // Rustls will enqueue the 'CloseNotify' alert and send it after
            // flushing the data that is already in the queue.
            self.tls.send_close_notify();
            self.wr_state = State::TlsClosing;
            continue;
          }
          State::TlsClosing if !self.tls.wants_write() => {
            self.wr_state = State::TlsClosed;
            continue;
          }
          // If a 'CloseNotify' alert sent by the remote end has been received,
          // shut down the underlying TCP socket. Otherwise, consider polling
          // done for the moment.
          State::TlsClosed if self.rd_state < State::TlsClosed => break true,
          State::TlsClosed if Pin::new(&mut self.tcp).poll_shutdown(cx)?.is_pending() => {
            break false;
          }
          State::TlsClosed => {
            self.wr_state = State::TcpClosed;
            continue;
          }
          State::TcpClosed => break true,
          _ => {}
        }

        // Write ciphertext to the TCP socket.
        let mut wrapped_tcp = ImplementWriteTrait(&mut self.tcp);
        match self.tls.write_tls(&mut wrapped_tcp) {
          Ok(0) => {}        // Wait until the socket has enough buffer space.
          Ok(_) => continue, // Try to send more more data immediately.
          Err(err) if err.kind() == ErrorKind::WouldBlock => unreachable!(),
          Err(err) => return Poll::Ready(Err(err)),
        }

        // Poll whether there is space in the socket send buffer so we can flush
        // the remaining outgoing ciphertext.
        if self.tcp.poll_write_ready(cx)?.is_pending() {
          break false;
        }
      };

      let rd_ready = loop {
        // Interpret and decrypt unprocessed TLS protocol data.
        let tls_state = self
          .tls
          .process_new_packets()
          .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        match self.rd_state {
          State::TcpClosed if self.tls.is_handshaking() => {
            let err = Error::new(ErrorKind::UnexpectedEof, "tls handshake eof");
            return Poll::Ready(Err(err));
          }
          _ if self.tls.is_handshaking() && !self.tls.wants_read() => {
            break true;
          }
          _ if self.tls.is_handshaking() => {}
          State::StreamOpen if tls_state.plaintext_bytes_to_read() > 0 => {
            break true;
          }
          State::StreamOpen if tls_state.peer_has_closed() => {
            self.rd_state = State::TlsClosed;
            continue;
          }
          State::StreamOpen => {}
          State::StreamClosed if tls_state.plaintext_bytes_to_read() > 0 => {
            // Rustls has more incoming cleartext buffered up, but the TLS
            // session is closing so this data will never be processed by the
            // application layer. Just like what would happen if this were a raw
            // TCP stream, don't gracefully end the TLS session, but abort it.
            return Poll::Ready(Err(Error::from(ErrorKind::ConnectionReset)));
          }
          State::StreamClosed => {}
          State::TlsClosed if self.wr_state == State::TcpClosed => {
            // Keep trying to read from the TCP connection until the remote end
            // closes it gracefully.
          }
          State::TlsClosed => break true,
          State::TcpClosed => break true,
          _ => unreachable!(),
        }

        // Try to read more TLS protocol data from the TCP socket.
        let mut wrapped_tcp = ImplementReadTrait(&mut self.tcp);
        match self.tls.read_tls(&mut wrapped_tcp) {
          Ok(0) => {
            self.rd_state = State::TcpClosed;
            continue;
          }
          Ok(_) => continue,
          Err(err) if err.kind() == ErrorKind::WouldBlock => {}
          Err(err) if err.kind() == ErrorKind::ConnectionReset => {
            // Rare, but happens more reliably when stepping through poll_io in a debugger after
            // remote TCP connection has been shut down. This suggests a race somewhere in this code.
            self.rd_state = State::TcpClosed;
            continue;
          }
          Err(err) => return Poll::Ready(Err(err)),
        }

        // Get notified when more ciphertext becomes available to read from the
        // TCP socket.
        if self.tcp.poll_read_ready(cx)?.is_pending() {
          break false;
        }
      };

      if wr_ready {
        if self.rd_state >= State::TlsClosed
          && self.wr_state >= State::TlsClosed
          && self.wr_state < State::TcpClosed
        {
          continue;
        }
        if self.tls.wants_write() {
          continue;
        }
      }

      let io_ready = match flow {
        _ if self.tls.is_handshaking() => false,
        Flow::Handshake => true,
        Flow::Read => rd_ready,
        Flow::Write => wr_ready,
      };
      return match io_ready {
        false => Poll::Pending,
        true => Poll::Ready(Ok(())),
      };
    }
  }

  pub(crate) fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    if self.tls.is_handshaking() {
      ready!(self.poll_io(cx, Flow::Handshake))?;
    }
    Poll::Ready(Ok(()))
  }

  pub(crate) fn poll_read(
    &mut self,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    ready!(self.poll_io(cx, Flow::Read))?;

    if self.rd_state == State::StreamOpen {
      // TODO(bartlomieju):
      #[allow(clippy::undocumented_unsafe_blocks)]
      let buf_slice = unsafe { &mut *(buf.unfilled_mut() as *mut [_] as *mut [u8]) };
      let bytes_read = self.tls.reader().read(buf_slice)?;
      assert_ne!(bytes_read, 0);
      // TODO(bartlomieju):
      #[allow(clippy::undocumented_unsafe_blocks)]
      unsafe {
        buf.assume_init(bytes_read)
      };
      buf.advance(bytes_read);
    }

    Poll::Ready(Ok(()))
  }

  pub(crate) fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    if buf.is_empty() {
      // Tokio-rustls compatibility: a zero byte write always succeeds.
      Poll::Ready(Ok(0))
    } else if self.wr_state == State::StreamOpen {
      // Flush Rustls' ciphertext send queue.
      ready!(self.poll_io(cx, Flow::Write))?;

      // Copy data from `buf` to the Rustls cleartext send queue.
      let bytes_written = self.tls.writer().write(buf)?;
      assert_ne!(bytes_written, 0);

      // Try to flush as much ciphertext as possible. However, since we just
      // handed off at least some bytes to rustls, so we can't return
      // `Poll::Pending()` any more: this would tell the caller that it should
      // try to send those bytes again.
      let _ = self.poll_io(cx, Flow::Write)?;

      Poll::Ready(Ok(bytes_written))
    } else {
      // Return error if stream has been shut down for writing.
      Poll::Ready(Err(ErrorKind::BrokenPipe.into()))
    }
  }

  pub(crate) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    if self.wr_state == State::StreamOpen {
      self.wr_state = State::StreamClosed;
    }

    ready!(self.poll_io(cx, Flow::Write))?;

    // At minimum, a TLS 'CloseNotify' alert should have been sent.
    assert!(self.wr_state >= State::TlsClosed);
    // If we received a TLS 'CloseNotify' alert from the remote end
    // already, the TCP socket should be shut down at this point.
    assert!(self.rd_state < State::TlsClosed || self.wr_state == State::TcpClosed);

    Poll::Ready(Ok(()))
  }

  pub(crate) fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    if self.rd_state == State::StreamOpen {
      self.rd_state = State::StreamClosed;
    }

    // Wait for the handshake to complete.
    ready!(self.poll_io(cx, Flow::Handshake))?;
    // Send TLS 'CloseNotify' alert.
    ready!(self.poll_shutdown(cx))?;
    // Wait for 'CloseNotify', shut down TCP stream, wait for TCP FIN packet.
    ready!(self.poll_io(cx, Flow::Read))?;

    assert_eq!(self.rd_state, State::TcpClosed);
    assert_eq!(self.wr_state, State::TcpClosed);

    Poll::Ready(Ok(()))
  }
}
