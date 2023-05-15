use rustls::Connection;
use std::backtrace::Backtrace;
use std::backtrace::BacktraceStatus;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::task::Poll;
use tokio::net::TcpStream;

#[inline(always)]
fn trace_error(error: io::Error) -> io::Error {
  #[cfg(debug_assertions)]
  {
    let backtrace = Backtrace::capture();
    if backtrace.status() == BacktraceStatus::Captured {
      println!("{error:?} {backtrace}");
    }
  }
  error
}

#[inline(always)]
fn trace_poll_error<T>(poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
  match poll {
    Poll::Pending => Poll::Pending,
    Poll::Ready(Ok(x)) => Poll::Ready(Ok(x)),
    Poll::Ready(Err(err)) => Poll::Ready(Err(trace_error(err))),
  }
}

pub struct ImplementReadTrait<'a, T>(pub &'a mut T);

impl Read for ImplementReadTrait<'_, TcpStream> {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    let res = self.0.try_read(buf);
    println!("r={:?}", res);
    match res {
      Ok(n) => Ok(n),
      Err(err) if err.kind() == ErrorKind::WouldBlock => Err(err),
      Err(err) => Err(trace_error(err)),
    }
  }
}

pub struct ImplementWriteTrait<'a, T>(pub &'a mut T);

impl Write for ImplementWriteTrait<'_, TcpStream> {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    match self.0.try_write(buf) {
      Ok(n) => Ok(n),
      Err(err) if err.kind() == ErrorKind::WouldBlock => Err(err),
      Err(err) => Err(trace_error(err)),
    }
  }

  fn flush(&mut self) -> io::Result<()> {
    Ok(())
  }
}

pub fn read_tls<'a, 'b>(tcp: &'a mut TcpStream, tls: &'b mut Connection) -> io::Result<usize> {
  let mut read = ImplementReadTrait(tcp);
  tls.read_tls(&mut read)
}

pub fn write_tls<'a, 'b>(tcp: &'a mut TcpStream, tls: &'b mut Connection) -> io::Result<usize> {
  let mut write = ImplementWriteTrait(tcp);
  tls.write_tls(&mut write)
}
