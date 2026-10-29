//! Interop with real clients: run `mosquitto_pub`/`mosquitto_sub` against a
//! tiny in-test TCP server that uses only this crate to decode and answer.
//! Skipped (with a note) when the mosquitto clients are not installed.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

use urmqtt_mqtt::*;

const LIMITS: Limits = Limits {
    max_packet_size: 65536,
    max_topic_len: 256,
    max_topic_levels: 16,
    max_client_id_len: 64,
    max_topics_per_packet: 8,
};

fn have(bin: &str) -> bool {
    Command::new(bin)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Reads one packet from `s`, buffering exactly what the decoder asks for.
fn read_packet(s: &mut TcpStream, buf: &mut Vec<u8>) -> Vec<u8> {
    try_read_packet(s, buf).expect("client closed early")
}

/// Like `read_packet`, but `None` if the client closed the connection.
fn try_read_packet(s: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    loop {
        match decode(buf, &LIMITS) {
            Ok((_, n)) => {
                let pkt = buf[..n].to_vec();
                buf.drain(..n);
                return Some(pkt);
            }
            Err(Error::Incomplete(_)) => {
                let mut chunk = [0u8; 4096];
                let n = s.read(&mut chunk).expect("read");
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) => panic!("decode error {e:?} on {buf:02x?}"),
        }
    }
}

fn send(s: &mut TcpStream, p: &Packet<'_>) {
    let mut out = vec![0u8; encoded_len(p)];
    encode(p, &mut out).unwrap();
    s.write_all(&out).unwrap();
}

#[test]
fn mosquitto_pub_qos1_with_will_and_credentials() {
    if !have("mosquitto_pub") {
        eprintln!("mosquitto_pub not installed: interop test skipped");
        return;
    }
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port().to_string();
    let child = Command::new("mosquitto_pub")
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port,
            "-V",
            "mqttv311",
            "-i",
            "device-001",
            "-q",
            "1",
            "-r",
            "-t",
            "devices/device-001/telemetry/temp",
            "-m",
            "{\"c\":21.5}",
            "-u",
            "user",
            "-P",
            "pass",
            "-k",
            "30",
            "--will-topic",
            "devices/device-001/status",
            "--will-payload",
            "offline",
            "--will-qos",
            "1",
            "--will-retain",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (mut s, _) = l.accept().unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = Vec::new();

    let bytes = read_packet(&mut s, &mut buf);
    let (p, _) = decode(&bytes, &LIMITS).unwrap();
    let Packet::Connect(c) = p else {
        panic!("expected CONNECT, got {p:?}")
    };
    assert_eq!(c.client_id, "device-001");
    assert_eq!(c.keep_alive, 30);
    assert_eq!(c.username, Some("user"));
    assert_eq!(c.password, Some(&b"pass"[..]));
    let w = c.will.expect("will");
    assert_eq!(
        (w.topic, w.payload, w.qos, w.retain),
        (
            "devices/device-001/status",
            &b"offline"[..],
            QoS::AtLeastOnce,
            true
        )
    );
    send(
        &mut s,
        &Packet::ConnAck(ConnAck {
            session_present: false,
            code: ConnectReturnCode::Accepted,
        }),
    );

    let bytes = read_packet(&mut s, &mut buf);
    let (p, _) = decode(&bytes, &LIMITS).unwrap();
    let Packet::Publish(pb) = p else {
        panic!("expected PUBLISH, got {p:?}")
    };
    assert_eq!(pb.topic, "devices/device-001/telemetry/temp");
    assert_eq!(pb.payload, b"{\"c\":21.5}");
    assert_eq!((pb.qos, pb.retain), (QoS::AtLeastOnce, true));
    send(&mut s, &Packet::PubAck(pb.packet_id.unwrap()));

    // mosquitto_pub 2.1 may close without DISCONNECT; anything it does send
    // must be a DISCONNECT.
    if let Some(bytes) = try_read_packet(&mut s, &mut buf) {
        assert_eq!(decode(&bytes, &LIMITS).unwrap().0, Packet::Disconnect);
    }
    drop(s);
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "mosquitto_pub failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn mosquitto_sub_subscribe_receive_ping() {
    if !have("mosquitto_sub") {
        eprintln!("mosquitto_sub not installed: interop test skipped");
        return;
    }
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port().to_string();
    let child = Command::new("mosquitto_sub")
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port,
            "-V",
            "mqttv311",
            "-i",
            "device-002",
            "-c",
            "-q",
            "1",
            "-t",
            "devices/device-002/cmd/#",
            "-t",
            "fleet/+/broadcast",
            "-C",
            "1",
            "-v",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (mut s, _) = l.accept().unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = Vec::new();

    let bytes = read_packet(&mut s, &mut buf);
    let Packet::Connect(c) = decode(&bytes, &LIMITS).unwrap().0 else {
        panic!()
    };
    assert!(!c.clean_session, "-c means persistent session");
    send(
        &mut s,
        &Packet::ConnAck(ConnAck {
            session_present: false,
            code: ConnectReturnCode::Accepted,
        }),
    );

    let bytes = read_packet(&mut s, &mut buf);
    let Packet::Subscribe(sub) = decode(&bytes, &LIMITS).unwrap().0 else {
        panic!()
    };
    let topics: Vec<_> = sub.topics.iter().collect();
    assert_eq!(
        topics,
        vec![
            ("devices/device-002/cmd/#", QoS::AtLeastOnce),
            ("fleet/+/broadcast", QoS::AtLeastOnce)
        ]
    );
    send(
        &mut s,
        &Packet::SubAck(SubAck {
            packet_id: sub.packet_id,
            return_codes: &[1, 1],
        }),
    );

    send(
        &mut s,
        &Packet::Publish(Publish {
            dup: false,
            qos: QoS::AtLeastOnce,
            retain: false,
            topic: "devices/device-002/cmd/reboot",
            packet_id: Some(42),
            payload: b"now",
        }),
    );
    let bytes = read_packet(&mut s, &mut buf);
    assert_eq!(decode(&bytes, &LIMITS).unwrap().0, Packet::PubAck(42));
    drop(s);
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "devices/device-002/cmd/reboot now"
    );
}
