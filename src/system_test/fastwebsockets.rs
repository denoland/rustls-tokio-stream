// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
use std::num::NonZeroUsize;
use std::time::Duration;

use fastwebsockets::FragmentCollectorRead;
use fastwebsockets::Frame;
use fastwebsockets::OpCode;
use fastwebsockets::Payload;
use fastwebsockets::Role;
use fastwebsockets::WebSocket;
use fastwebsockets::WebSocketError;
use rstest::rstest;
use tokio::sync::Mutex;

const LARGE_PAYLOAD: [u8; 48 * 1024] = [0xff; 48 * 1024];
const SMALL_PAYLOAD: [u8; 16] = [0xff; 16];

#[rstest]
#[case(false, false, false, false)]
#[case(false, false, false, true)]
#[case(false, false, true, false)]
#[case(false, false, true, true)]
#[case(false, true, false, false)]
#[case(false, true, false, true)]
#[case(false, true, true, false)]
#[case(false, true, true, true)]
#[case(true, false, false, false)]
#[case(true, false, false, true)]
#[case(true, false, true, false)]
#[case(true, false, true, true)]
#[case(true, true, false, false)]
#[case(true, true, false, true)]
#[case(true, true, true, false)]
#[case(true, true, true, true)]
#[tokio::test]
async fn test_fastwebsockets(
  #[case] handshake: bool,
  #[case] buffer_limit: bool,
  #[case] large_payload: bool,
  #[case] use_writev: bool,
) {
  let payload = if large_payload {
    LARGE_PAYLOAD.as_slice()
  } else {
    SMALL_PAYLOAD.as_slice()
  };
  let (mut client, mut server) = if buffer_limit {
    crate::tests::tls_pair_buffer_size(Some(
      NonZeroUsize::try_from(1024).unwrap(),
    ))
    .await
  } else {
    crate::tests::tls_pair().await
  };
  if handshake {
    client.handshake().await.expect("failed handshake");
    server.handshake().await.expect("failed handshake");
  }

  let a = tokio::spawn(async move {
    let mut ws = WebSocket::after_handshake(server, Role::Server);
    ws.set_auto_close(true);
    if use_writev {
      ws.set_writev(true);
      ws.set_writev_threshold(0);
    }
    for i in 0..1000 {
      println!("send {i}");
      ws.write_frame(Frame::binary(Payload::Borrowed(payload)))
        .await
        .expect("failed to write");
    }
    let frame = ws.read_frame().await.expect("failed to read");
    assert_eq!(frame.payload.len(), payload.len());
    ws.write_frame(Frame::close(1000, &[]))
      .await
      .expect("failed to close");
    let frame = ws.read_frame().await.expect("failed to read");
    assert_eq!(frame.opcode, OpCode::Close);
  });
  let b = tokio::spawn(async move {
    let mut ws = WebSocket::after_handshake(client, Role::Client);
    if use_writev {
      ws.set_writev(true);
      ws.set_writev_threshold(0);
    }
    ws.set_auto_close(true);
    for i in 0..1000 {
      println!("recv {i}");
      let frame = ws.read_frame().await.expect("failed to read");
      assert_eq!(frame.payload.len(), payload.len());
    }
    ws.write_frame(Frame::binary(Payload::Borrowed(payload)))
      .await
      .expect("failed to write");
    let frame = ws.read_frame().await.expect("failed to read");
    assert_eq!(frame.opcode, OpCode::Close);
  });

  a.await.expect("failed to join");
  b.await.expect("failed to join");
}

#[tokio::test]
async fn test_fastwebsockets_split_echo() {
  let (mut client, mut server) = crate::tests::tls_pair_buffer_size(Some(
    NonZeroUsize::try_from(65536).unwrap(),
  ))
  .await;

  client.handshake().await.expect("failed handshake");
  server.handshake().await.expect("failed handshake");
  println!("===handshakes done===");

  let a = tokio::spawn(async {
    let mut ws = WebSocket::after_handshake(server, Role::Server);
    ws.set_auto_close(true);
    loop {
      let frame = ws.read_frame().await.unwrap();
      match frame.opcode {
        OpCode::Close => break,
        OpCode::Text | OpCode::Binary => {
          println!("got frame");
          ws.write_frame(frame).await.expect("Failed to write");
        }
        _ => {}
      }
    }
    println!("a ended");
  });
  let b = tokio::spawn(async {
    let ws = WebSocket::after_handshake(client, Role::Client);
    let (rx, mut tx) = ws.split(tokio::io::split);
    let mut rx = FragmentCollectorRead::new(rx);
    let b1 = tokio::spawn(async move {
      let frame = rx
        .read_frame::<_, WebSocketError>(&mut |_| async { unimplemented!() })
        .await
        .expect("Failed to read");
      assert_eq!(frame.payload.len(), 65000);
      println!("b1 ended");
    });

    tokio::task::yield_now().await;

    let b2 = tokio::spawn(async move {
      tx.write_frame(Frame::binary(Payload::Owned(vec![b'a'; 65000])))
        .await
        .expect("Failed to write packet");
      tx.write_frame(Frame::close(1000, &[]))
        .await
        .expect("Failed to write close");
      println!("b2 ended");
    });

    b2.await.expect("failed to join");
    b1.await.expect("failed to join");
    println!("b ended");
  });

  a.await.expect("failed to join");
  b.await.expect("failed to join");
}

#[tokio::test]
async fn test_fastwebsockets_split_ping_pong() {
  let (mut client, mut server) = crate::tests::tls_pair_buffer_size(Some(
    NonZeroUsize::try_from(65536).unwrap(),
  ))
  .await;

  client.handshake().await.expect("failed handshake");
  server.handshake().await.expect("failed handshake");
  println!("===handshakes done===");

  let a = tokio::spawn(async {
    let mut ws = WebSocket::after_handshake(server, Role::Server);
    ws.set_auto_close(false);
    let (mut rx, tx) = ws.split(tokio::io::split);
    let tx = std::sync::Arc::new(Mutex::new(tx));
    loop {
      let frame = rx
        .read_frame::<_, WebSocketError>(&mut |_| async { unimplemented!() })
        .await
        .unwrap();
      match frame.opcode {
        OpCode::Close => break,
        OpCode::Text | OpCode::Binary => {
          println!("got frame");
          let tx = tx.clone();
          let payload = frame.payload.to_vec();
          tokio::task::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tx.lock()
              .await
              .write_frame(Frame::binary(Payload::Owned(payload)))
              .await
              .expect("Failed to write");
          });
        }
        _ => {}
      }
    }
    println!("a ended");
  });
  let b = tokio::spawn(async {
    let ws = WebSocket::after_handshake(client, Role::Client);
    let (rx, mut tx) = ws.split(|ws| ws.into_split());
    let mut rx = FragmentCollectorRead::new(rx);
    let b1 = tokio::spawn(async move {
      for _i in 0..2 {
        let frame = rx
          .read_frame::<_, WebSocketError>(&mut |_| async { unimplemented!() })
          .await
          .expect("Failed to read");
        assert_eq!(frame.payload.len(), 65000);
      }
      println!("b1 ended");
    });

    tokio::task::yield_now().await;

    let b2 = tokio::spawn(async move {
      tx.write_frame(Frame::binary(Payload::Owned(vec![b'a'; 65000])))
        .await
        .expect("Failed to write packet");
      tokio::time::sleep(Duration::from_millis(200)).await;
      tx.write_frame(Frame::binary(Payload::Owned(vec![b'a'; 65000])))
        .await
        .expect("Failed to write packet");
      tokio::time::sleep(Duration::from_millis(200)).await;
      tx.write_frame(Frame::close(1000, &[]))
        .await
        .expect("Failed to write close");
      println!("b2 ended");
    });

    b2.await.expect("failed to join");
    b1.await.expect("failed to join");
    println!("b ended");
  });

  a.await.expect("failed to join");
  b.await.expect("failed to join");
}
