use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Weak;
use std::task::Context;
use std::task::Poll;
use std::task::RawWaker;
use std::task::RawWakerVTable;
use std::task::Waker;
use futures::task::AtomicWaker;

enum WakerHalf {
    Read,
    Write,
}

pub struct ReadHalf<S> {
  shared: Arc<Shared<S>>,
}

impl ReadHalf<S> {
  pub fn reunite(self, wr: WriteHalf) -> S {
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
