use std::num::NonZeroUsize;

use fastwebsockets::FragmentCollectorRead;
use fastwebsockets::Frame;
use fastwebsockets::OpCode;
use fastwebsockets::Payload;
use fastwebsockets::Role;
use fastwebsockets::WebSocket;
use fastwebsockets::WebSocketError;
use rstest::rstest;

const LARGE_PAYLOAD: [u8; 48 * 1024] = [0xff; 48 * 1024];
const SMALL_PAYLOAD: [u8; 16] = [0xff; 16];

#[rstest]
#[case(false, false, false)]
#[case(false, false, true)]
#[case(false, true, false)]
#[case(false, true, true)]
#[case(true, false, false)]
#[case(true, false, true)]
#[case(true, true, false)]
#[case(true, true, true)]
#[tokio::test]
async fn test_fastwebsockets(
  #[case] handshake: bool,
  #[case] buffer_limit: bool,
  #[case] large_payload: bool,
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

  let a = tokio::spawn(async {
    let mut ws = WebSocket::after_handshake(server, Role::Server);
    ws.set_auto_close(true);
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
  let b = tokio::spawn(async {
    let mut ws = WebSocket::after_handshake(client, Role::Client);
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
    let (rx, mut tx) = ws.split(|ws| tokio::io::split(ws));
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
      tx.write_frame(Frame::binary(Payload::Owned(vec!['a' as u8; 65000])))
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
