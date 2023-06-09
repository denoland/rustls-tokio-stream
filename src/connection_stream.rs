use rustls::Connection;
use rustls::IoState;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::pin::Pin;
use std::task::ready;
use std::task::Context;
use std::task::Poll;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;

use crate::adapter::read_tls;
use crate::adapter::write_tls;

pub struct ConnectionStream {
  tls: Connection,
  tcp: TcpStream,
  last_iostate: Option<IoState>,
  /// If poll_shutdown has been called at least once
  wants_close_sent: bool,
  /// If we're successfully sent CLOSE_NOTIFY
  close_sent: bool,
  /// An error on the TLS read protocol stream.
  rd_proto_error: Option<rustls::Error>,
  /// An error on the underlying socket's read side.
  rd_error: Option<io::ErrorKind>,
  /// An error on the underlying socket's write side.
  wr_error: Option<io::ErrorKind>,
}

#[derive(Debug, PartialEq, Eq)]
enum StreamProgress {
  NoInterest,
  RegisteredWaker,
  MadeProgress,
  Error,
}

impl ConnectionStream {
  pub fn new(tcp: TcpStream, tls: Connection) -> Self {
    Self {
      tls,
      tcp,
      wants_close_sent: false,
      close_sent: false,
      last_iostate: None,
      rd_proto_error: None,
      rd_error: None,
      wr_error: None,
    }
  }

  fn plaintext_bytes_to_read(&self) -> usize {
    self
      .last_iostate
      .as_ref()
      .map(|iostate| iostate.plaintext_bytes_to_read())
      .unwrap_or_default()
  }

  fn tls_bytes_to_write(&self) -> usize {
    self
      .last_iostate
      .as_ref()
      .map(|iostate| iostate.tls_bytes_to_write())
      .unwrap_or_default()
  }

  fn poll_read_only(&mut self, cx: &mut Context<'_>) -> StreamProgress {
    if self.rd_error.is_some() || self.rd_proto_error.is_some() {
      StreamProgress::Error
    } else if self.tls.wants_read() {
      loop {
        match read_tls(&mut self.tcp, &mut self.tls) {
          Ok(n) => {
            if n == 0 {
              self.rd_error = Some(ErrorKind::UnexpectedEof);
            }
            match self.tls.process_new_packets() {
              Ok(iostate) => {
                self.last_iostate = Some(iostate);
                break StreamProgress::MadeProgress;
              }
              Err(err) => {
                self.rd_proto_error = Some(err);
                break StreamProgress::Error;
              }
            }
          }
          Err(err) if err.kind() == ErrorKind::WouldBlock => {
            match self.tcp.poll_read_ready(cx) {
              Poll::Pending => break StreamProgress::RegisteredWaker,
              Poll::Ready(Err(err)) => {
                self.rd_error = Some(err.kind());
                break StreamProgress::Error;
              }
              Poll::Ready(Ok(())) => {
                // It wasn't ready before but now it is, so try again.
                continue;
              }
            }
          }
          Err(err) => {
            self.rd_error = Some(err.kind());
            break StreamProgress::Error;
          }
        }
      }
    } else {
      StreamProgress::NoInterest
    }
  }

  fn poll_write_only(&mut self, cx: &mut Context<'_>) -> StreamProgress {
    if self.wr_error.is_some() {
      StreamProgress::Error
    } else if self.tls.wants_write() {
      loop {
        debug_assert!(self.tls.wants_write());
        match write_tls(&mut self.tcp, &mut self.tls) {
          Ok(n) => {
            assert!(n > 0);
            break StreamProgress::MadeProgress;
          }
          Err(err) if err.kind() == ErrorKind::WouldBlock => {
            match self.tcp.poll_write_ready(cx) {
              Poll::Pending => break StreamProgress::RegisteredWaker,
              Poll::Ready(Err(err)) => {
                self.wr_error = Some(err.kind());
                break StreamProgress::Error;
              }
              Poll::Ready(Ok(())) => {
                continue;
              }
            }
          }
          Err(err) => {
            self.wr_error = Some(err.kind());
            break StreamProgress::Error;
          }
        }
      }
    } else {
      StreamProgress::NoInterest
    }
  }

  /// Perform a read operation on this connection.
  fn try_read(&mut self, buf: &mut ReadBuf<'_>) -> io::Result<usize> {
    // SAFETY: We're going to fill this buffer and mark it as filled according to how much we actually read
    let buf_slice =
      unsafe { &mut *(buf.unfilled_mut() as *mut [_] as *mut [u8]) };

    match self.tls.reader().read(buf_slice) {
      Ok(n) if n == 0 => {
        println!("r*={n}");
        // EOF
        Ok(0)
      }
      Ok(n) => {
        println!("r*={n}");
        // SAFETY: We know we read this much into the buffer
        unsafe { buf.assume_init(n) };
        buf.advance(n);
        Ok(n)
      }
      // One of the two errors that reader().read can return: this is not associated with the non-blocking
      // errors on the underlying TCP stream, it just means we have no data available.
      Err(err) if err.kind() == ErrorKind::WouldBlock => {
        println!("r*={err:?}");
        // No data to read, but we need to make sure we don't have an error state here.
        if self.rd_proto_error.is_some() {
          // TODO: Should we expose the underlying TLS error?
          Err(ErrorKind::InvalidData.into())
        } else if let Some(err) = self.rd_error {
          // We have a connection error
          Err(err.into())
        } else {
          // No error, just don't have data
          Err(err)
        }
      }
      // This is the only other error that reader().read method can legitimately return, and it happens if the other
      // side fails to close the connection cleanly.
      Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
        println!("r*={err:?}");
        self.rd_error = Some(ErrorKind::UnexpectedEof);
        Err(err)
      }
      Err(_) => {
        // rustls will not return other errors here
        unreachable!()
      }
    }
  }

  /// Polls the connection for read, writing as needed. As TLS may need to pump writes during reads, or
  /// pump reads during writes, we must ensure that the waker is woken if writes are ready, even though
  /// this is a read polling operation.
  ///
  /// Should writes error at any point, we disable the write portion of the polling operation.
  ///
  /// This function will return [`Poll::Pending`] if reads were unable to progress at all.
  ///
  /// The waker will be woken if either reads or writes may be able to make further progress.
  pub fn poll_read(
    &mut self,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<usize>> {
    loop {
      // First prepare to read
      let read = self.poll_read_only(cx);

      // Then write until we lose interest
      loop {
        let write = self.poll_write_only(cx);
        if write != StreamProgress::MadeProgress {
          break;
        }
      }

      match read {
        StreamProgress::RegisteredWaker => break Poll::Pending,
        StreamProgress::MadeProgress
        | StreamProgress::NoInterest
        | StreamProgress::Error => {
          match self.try_read(buf) {
            Ok(n) => break Poll::Ready(Ok(n)),
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
              // Spurious wakeup, retry
              continue;
            }
            Err(err) => break Poll::Ready(Err(err)),
          }
        }
      }
    }
  }

  /// Polls the connection for writes, reading as needed. As TLS may need to pump writes during reads, or
  /// pump reads during writes, we must ensure that the waker is woken if reads are ready, even though
  /// this is a write polling operation.
  ///
  /// Should reads error at any point, we disable the read portion of the polling operation.
  ///
  /// This function will return [`Poll::Pending`] if writes were unable to progress at all.
  ///
  /// The waker will be woken if either reads or writes may be able to make further progress.
  pub fn poll_write(
    &mut self,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    // Zero-length writes always succeed
    if buf.len() == 0 {
      return Poll::Ready(Ok(0));
    }

    // Writes after shutdown return NotConnected
    if self.wants_close_sent {
      return Poll::Ready(Err(ErrorKind::NotConnected.into()));
    }

    // First prepare to write
    let res = loop {
      let write = self.poll_write_only(cx);
      match write {
        // No room to write
        StreamProgress::RegisteredWaker => break Poll::Pending,
        // We wrote something, so let's loop again
        StreamProgress::MadeProgress => continue,
        // Wedged on an error
        StreamProgress::Error => {
          break Poll::Ready(Err(self.wr_error.unwrap().into()))
        }
        // No current write interest, so let's generate some
        StreamProgress::NoInterest => {
          // Write it
          let n = self.tls.writer().write(buf).expect("Write will never fail");
          assert!(n > 0);
          // Drain what we can
          while self.poll_write_only(cx) == StreamProgress::MadeProgress {}
          // And then return what we wrote
          break Poll::Ready(Ok(n));
        }
      };
    };

    // Then read until we lose interest
    while self.poll_read_only(cx) == StreamProgress::MadeProgress {}

    res
  }

  /// Polls for completion of all the writes in the rustls [`Connection`]. Does not progress on
  /// reads at all.
  pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    loop {
      match self.poll_write_only(cx) {
        StreamProgress::RegisteredWaker => break Poll::Pending,
        StreamProgress::MadeProgress => continue,
        StreamProgress::NoInterest => break Poll::Ready(Ok(())),
        StreamProgress::Error => {
          println!("flush={}", self.wr_error.unwrap());
          break Poll::Ready(Err(self.wr_error.unwrap().into()));
        }
      }
    }
  }

  /// Polls for completion of all the writes in the rustls [`Connection`]. Does not progress on
  /// reads at all.
  pub fn poll_shutdown(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    // Immediate state change so we can error writes
    self.wants_close_sent = true;
    if !self.close_sent {
      ready!(self.poll_flush(cx))?;
      self.tls.send_close_notify();
      self.close_sent = true;
    }
    ready!(self.poll_flush(cx))?;
    // Note that this is not technically an async call
    // TODO(mmastrac): This is currently untested
    _ = Pin::new(&mut self.tcp).poll_shutdown(cx);
    Poll::Ready(Ok(()))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::handshake::handshake_task;
  use crate::tests::client_config;
  use crate::tests::server_config;
  use crate::tests::server_name;
  use crate::tests::tcp_pair;
  use crate::tests::TestResult;
  use futures::future::poll_fn;
  use futures::task::noop_waker_ref;
  use rustls::ClientConnection;
  use rustls::ServerConnection;
  use std::time::Duration;
  use tokio::io::AsyncReadExt;
  use tokio::io::AsyncWriteExt;
  use tokio::spawn;

  async fn expect_write_1(mut conn: &mut ConnectionStream) {
    assert_eq!(poll_fn(|cx| conn.poll_write(cx, b"x")).await.unwrap(), 1);
  }

  async fn wait_for_peek(mut conn: &mut ConnectionStream) {
    loop {
      let mut buf = [0; 1];
      if conn.tcp.peek(&mut buf).await.unwrap() == 1 {
        return;
      }
    }
  }

  async fn wait_for_peek_n<const N: usize>(mut conn: &mut ConnectionStream) {
    loop {
      let mut buf = [0; N];
      if conn.tcp.peek(&mut buf).await.unwrap() == N {
        return;
      }
      tokio::time::sleep(Duration::from_millis(1)).await;
    }
  }

  async fn expect_read_1(mut conn: &mut ConnectionStream) {
    let mut buf = [0; 1];
    let mut read_buf = ReadBuf::new(&mut buf);
    assert_eq!(
      poll_fn(|cx| conn.poll_read(cx, &mut read_buf))
        .await
        .unwrap(),
      1
    );
  }

  async fn expect_read_1_err(
    mut conn: &mut ConnectionStream,
    error: ErrorKind,
  ) {
    let mut buf = [0; 1];
    let mut read_buf = ReadBuf::new(&mut buf);
    let err = poll_fn(|cx| conn.poll_read(cx, &mut read_buf))
      .await
      .expect_err("expected error");
    assert_eq!(err.kind(), error);
  }

  async fn tls_pair() -> (ConnectionStream, ConnectionStream) {
    let (server, client) = crate::tests::tcp_pair().await;
    let tls_server = ServerConnection::new(server_config().into())
      .unwrap()
      .into();
    let tls_client =
      ClientConnection::new(client_config().into(), server_name())
        .unwrap()
        .into();
    let server = spawn(handshake_task(server, tls_server));
    let client = spawn(handshake_task(client, tls_client));
    let (tcp_client, tls_client) = client.await.unwrap().unwrap();
    let (tcp_server, tls_server) = server.await.unwrap().unwrap();
    assert!(!tls_client.is_handshaking());
    assert!(!tls_server.is_handshaking());

    (
      ConnectionStream::new(tcp_server, tls_server),
      ConnectionStream::new(tcp_client, tls_client),
    )
  }

  /// One byte read/write, don't check close.
  #[tokio::test]
  async fn test_connection_stream() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    expect_write_1(&mut client).await;
    expect_read_1(&mut server).await;
    Ok(())
  }

  /// One byte read/write, don't check close.
  #[tokio::test]
  async fn test_connection_stream_shutdown() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    expect_write_1(&mut client).await;
    expect_read_1(&mut server).await;

    let cx = &mut Context::from_waker(noop_waker_ref());
    // Start the shutdown process
    _ = server.poll_shutdown(cx);
    // Writes immediately fail
    match server.poll_write(cx, &[0]) {
      Poll::Ready(Err(err)) => {
        assert_eq!(err.kind(), ErrorKind::NotConnected);
      }
      _ => {
        panic!("Should have failed");
      }
    };
    Ok(())
  }

  /// Dirty half close.
  #[tokio::test]
  async fn test_connection_stream_dirty_close() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    expect_write_1(&mut client).await;

    // Half-close
    client.tcp.shutdown().await?;

    // One byte will read fine
    expect_read_1(&mut server).await;

    // The next byte will return UnexpectedEof
    expect_read_1_err(&mut server, ErrorKind::UnexpectedEof).await;

    Ok(())
  }

  /// Dirty close (abort). This doesn't pass on Windows because the read appears to send the
  /// connection reset error rather than any socket contents.
  #[cfg(not(target_os = "windows"))]
  #[tokio::test]
  async fn test_connection_stream_dirty_close_abort() -> TestResult {
    let (mut server, mut client) = tls_pair().await;

    // We're testing aborts, so set NODELAY and linger=0 on the socket
    client.tcp.set_nodelay(true).unwrap();
    client.tcp.set_linger(Some(Duration::default()))?;

    expect_write_1(&mut client).await;
    wait_for_peek_n::<23>(&mut server).await;

    // Abortive close
    drop(client);

    // One byte will read fine
    expect_read_1(&mut server).await;

    // The next byte will not
    expect_read_1_err(&mut server, ErrorKind::ConnectionReset).await;
    Ok(())
  }

  /// Associated test for [`test_connection_stream_dirty_close_abort`]. If this test fails,
  /// the OS in question throws away unreceived data on reset.
  #[cfg(not(target_os = "windows"))]
  #[tokio::test]
  async fn test_tcp_abort() -> TestResult {
    let (mut server, mut client) = tcp_pair().await;
    client.set_nodelay(true).unwrap();
    client.set_linger(Some(Duration::default())).unwrap();
    client.write_u8(0).await;
    client.flush().await;
    drop(client);

    server.readable().await.unwrap();

    let mut buf = [0; 19000];
    server.try_read(buf.as_mut_slice()).unwrap();
    server
      .try_read(buf.as_mut_slice())
      .expect_err("expected reset");

    Ok(())
  }

  /// Half close.
  #[tokio::test]
  async fn test_connection_stream_half_close() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    expect_write_1(&mut client).await;

    // Half-close
    client.tcp.shutdown().await?;

    // One byte will read fine
    expect_read_1(&mut server).await;

    // Server can still write
    expect_write_1(&mut server).await;

    // Client can still read
    expect_read_1(&mut client).await;

    // The next server byte will not read.
    expect_read_1_err(&mut server, ErrorKind::UnexpectedEof).await;

    Ok(())
  }

  /// Corrupt data.
  #[tokio::test]
  async fn test_connection_stream_bad_data() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    expect_write_1(&mut client).await;

    // One byte will read fine
    expect_read_1(&mut server).await;

    client
      .tcp
      .write_all(b"THIS IS NOT A VALID TLS PACKET")
      .await?;

    // The next byte will not
    expect_read_1_err(&mut server, ErrorKind::InvalidData).await;
    Ok(())
  }

  /// Corrupt data.
  #[tokio::test]
  async fn test_connection_stream_bad_data_2() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    expect_write_1(&mut client).await;
    wait_for_peek(&mut server).await;

    // This forces the server to read as well, buffering the single valid packet
    assert_eq!(server.plaintext_bytes_to_read(), 0);
    expect_write_1(&mut server).await;
    assert_ne!(server.plaintext_bytes_to_read(), 0);

    client
      .tcp
      .write_all(b"THIS IS NOT A VALID TLS PACKET")
      .await?;

    // One byte will read fine
    expect_read_1(&mut server).await;

    // The next byte will not
    expect_read_1_err(&mut server, ErrorKind::InvalidData).await;

    Ok(())
  }

  #[tokio::test]
  async fn test_connection_flush() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    let buf = [0x42; 1024];
    let mut cx = Context::from_waker(noop_waker_ref());

    // Write as much as we can to the socket until poll starts returning Pending
    let mut total = 0;
    while let Poll::Ready(n) = server.poll_write(&mut cx, buf.as_slice()) {
      total += n.unwrap();
    }

    server.tls.writer().write(b"final")?;
    let iostate = server.tls.process_new_packets().unwrap();

    assert!(iostate.tls_bytes_to_write() > 0);

    // We can't make progress
    assert!(server.poll_flush(&mut cx).is_pending());

    // Read half of what we wrote
    let mut buf = [0; 1024];
    let mut total_read = 0;
    while total_read < total / 2 {
      let mut read_buf = ReadBuf::new(&mut buf);
      total_read += poll_fn(|cx| client.poll_read(cx, &mut read_buf))
        .await
        .unwrap();
    }

    // Now we can flush
    poll_fn(|cx| server.poll_flush(cx)).await.unwrap();
    let iostate = server.tls.process_new_packets().unwrap();
    assert!(iostate.tls_bytes_to_write() == 0);

    Ok(())
  }

  #[tokio::test]
  async fn test_connection_clean_close() -> TestResult {
    let (mut server, mut client) = tls_pair().await;
    let buf = [0x42; 1024];
    let mut cx = Context::from_waker(noop_waker_ref());

    // Write as much as we can to the socket until poll starts returning Pending
    let mut total = 0;
    while let Poll::Ready(n) = server.poll_write(&mut cx, buf.as_slice()) {
      total += n.unwrap();
    }

    server.tls.writer().write(b"final")?;
    let iostate = server.tls.process_new_packets().unwrap();

    assert!(iostate.tls_bytes_to_write() > 0);

    // We can't make progress
    assert!(server.poll_shutdown(&mut cx).is_pending());

    // Read half of what we wrote
    let mut buf = [0; 1024];
    let mut total_read = 0;
    while total_read < total / 2 {
      let mut read_buf = ReadBuf::new(&mut buf);
      total_read += poll_fn(|cx| client.poll_read(cx, &mut read_buf))
        .await
        .unwrap();
    }

    // Now we can shutdown
    poll_fn(|cx| server.poll_shutdown(cx)).await.unwrap();
    let iostate = server.tls.process_new_packets().unwrap();
    assert!(iostate.tls_bytes_to_write() == 0);

    loop {
      let mut read_buf = ReadBuf::new(&mut buf);
      let n = poll_fn(|cx| client.poll_read(cx, &mut read_buf))
        .await
        .unwrap();
      total_read += n;
      if n == 0 {
        // 5 extra from the "final" packet
        assert_eq!(total_read, total + 5);
        break;
      }
    }

    Ok(())
  }
}
