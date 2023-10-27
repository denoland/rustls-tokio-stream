use std::num::NonZeroUsize;

use fastwebsockets::Frame;
use fastwebsockets::OpCode;
use fastwebsockets::Payload;
use fastwebsockets::Role;
use fastwebsockets::WebSocket;
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
    for _ in 0..1000 {
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
    for _ in 0..1000 {
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
