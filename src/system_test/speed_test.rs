use std::num::NonZeroUsize;
use std::time::Instant;

use crate::tests::tls_pair_buffer_size;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::spawn;

#[tokio::test(flavor = "multi_thread")]
async fn streaming_speed_test() {
  const BUF_SIZE: usize = 10 * 1024 * 1024;
  const BUF_COUNT: usize = 128;

  let now = Instant::now();
  let (server, client) = tls_pair_buffer_size(NonZeroUsize::new(65536)).await;
  let a = spawn(async move {
    let write_vec = vec![0; BUF_SIZE];
    let (mut r, mut w) = server.into_split();
    for _ in 0..BUF_COUNT {
      w.write_all(&write_vec).await.unwrap();
    }
    r.read_u8().await.unwrap()
  });
  let b = spawn(async move {
    let (mut r, mut w) = client.into_split();
    let mut read_vec = vec![0_u8; BUF_SIZE];
    for _ in 0..BUF_COUNT {
      r.read_exact(&mut read_vec).await.unwrap();
    }
    w.write_u8(0).await.unwrap();
  });
  a.await.unwrap();
  b.await.unwrap();
  eprintln!(
    "send = {} MB, elapsed = {} ms",
    BUF_COUNT * BUF_SIZE / (1024 * 1024),
    now.elapsed().as_secs_f32() * 1000_f32
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn speed_test() {}
