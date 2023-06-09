use crate::trace;
use rustls::Connection;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use tokio::net::TcpStream;

#[inline(always)]
fn trace_error(error: io::Error) -> io::Error {
  #[cfg(all(debug_assertions, feature = "trace"))]
  {
    use std::backtrace::Backtrace;
    use std::backtrace::BacktraceStatus;

    let backtrace = Backtrace::capture();
    if backtrace.status() == BacktraceStatus::Captured {
      trace!("{error:?} {backtrace}");
    }
  }
  error
}

pub struct ImplementReadTrait<'a, T>(pub &'a mut T);

impl Read for ImplementReadTrait<'_, TcpStream> {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    let res = self.0.try_read(buf);
    trace!("r({})={:?}", buf.len(), res);
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
    let res = self.0.try_write(buf);
    trace!("w={:?}", res);
    match res {
      Ok(n) => Ok(n),
      Err(err) if err.kind() == ErrorKind::WouldBlock => Err(err),
      Err(err) => Err(trace_error(err)),
    }
  }

  fn flush(&mut self) -> io::Result<()> {
    Ok(())
  }
}

pub fn read_tls(
  tcp: &mut TcpStream,
  tls: &mut Connection,
) -> io::Result<usize> {
  let mut read = ImplementReadTrait(tcp);
  tls.read_tls(&mut read)
}

pub fn write_tls(
  tcp: &mut TcpStream,
  tls: &mut Connection,
) -> io::Result<usize> {
  let mut write = ImplementWriteTrait(tcp);
  tls.write_tls(&mut write)
}
