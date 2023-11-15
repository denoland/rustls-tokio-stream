// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
use crate::trace;
use rustls::server::Acceptor;
use rustls::Connection;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use tokio::net::TcpStream;

/// Convert a [`rustls::Error`] to an [`io::Error`]
pub fn rustls_to_io_error(error: rustls::Error) -> io::Error {
  io::Error::new(ErrorKind::InvalidData, error)
}

/// Clones an [`io::Result`], assuming the inner error, if any, is a [`rustls::Error`].
pub fn clone_result<T: Clone>(result: &io::Result<T>) -> io::Result<T> {
  match result {
    Ok(t) => Ok(t.clone()),
    Err(e) => Err(clone_error(e)),
  }
}

/// Clones an [`io::Error`], assuming the inner error, if any, is a [`rustls::Error`].
pub fn clone_error(e: &io::Error) -> io::Error {
  let kind = e.kind();
  match e.get_ref() {
    Some(e) => match e.downcast_ref::<rustls::Error>() {
      Some(e) => io::Error::new(kind, e.clone()),
      None => kind.into(),
    },
    None => kind.into(),
  }
}

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

pub struct ImplementReadTrait<'a, T>(pub &'a T);

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

pub struct ImplementWriteTrait<'a, T>(pub &'a T);

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

pub fn read_tls(tcp: &TcpStream, tls: &mut Connection) -> io::Result<usize> {
  let mut read = ImplementReadTrait(tcp);
  tls.read_tls(&mut read)
}

pub fn write_tls(tcp: &TcpStream, tls: &mut Connection) -> io::Result<usize> {
  let mut write = ImplementWriteTrait(tcp);
  tls.write_tls(&mut write)
}

pub fn read_acceptor(
  tcp: &TcpStream,
  acceptor: &mut Acceptor,
) -> io::Result<usize> {
  let mut read = ImplementReadTrait(tcp);
  acceptor.read_tls(&mut read)
}
