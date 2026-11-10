//! H3: scripted TCP edge cases (RFC 9293, RFC 5961), see `script.rs` for
//! the language. Each script states what the stack must do, segment by
//! segment.

use alloc::format;

use crate::script::{cfg, run, run_with, run6};
use crate::{MAX_MSS, MIN_MSS, cookie, mss_for_mtu};

/// Three-way handshake through the SYN cookie, data both ways, the
/// client's close.
const HANDSHAKE: &str = "
< S seq=0 mss=1460
> S. seq=0 ack=1 mss=1460
< . seq=1 ack=1
expect conns=1
< P. seq=1 ack=1 len=100
> . ack=101
expect data=100
app send 10
> P. seq=1 ack=101 len=10
< . ack=11
< F. seq=101 ack=11
> . ack=102
expect peer_closed
app close
> F. seq=11 ack=102
< . seq=102 ack=12
expect conns=0
";

#[test]
fn handshake_data_and_close() {
    run(HANDSHAKE);
}

const OPEN: &str = "
< S seq=0 mss=1460
> S. seq=0 ack=1
< . seq=1 ack=1
";

fn with_open(rest: &str) {
    run(&format!("{OPEN}{rest}"));
}

/// Both sides close at once (RFC 9293 §3.6, simultaneous close): the FINs
/// cross; each acknowledges the other's and the connection ends.
#[test]
fn simultaneous_close() {
    with_open(
        "
app close
> F. seq=1 ack=1
< F. seq=1 ack=1          # sent before our FIN arrived: acks only data
> . ack=2
< . seq=2 ack=2
expect conns=0 peer_closed
",
    );
}

/// We close first; the peer acknowledges our FIN but keeps its own side
/// open (CLOSE-WAIT: a device whose application stopped reading, a keep-alive
/// timeout). FIN-WAIT-2 sends nothing more, however often the peer
/// acknowledges, and its timer ends the connection after 60 s (RFC 9293
/// §3.6, ADR-261). Before, every ACK of our FIN made `transmit` send a new FIN
/// one sequence number further (FIN_QUEUED was still set and the acknowledged
/// data was gone, so the FIN looked unsent), the peer acknowledged that one
/// too, and the pair exchanged segments as fast as both could forever: the
/// retransmission timer armed for each new FIN also replaced the FIN-WAIT-2
/// timer. QEMU's user-mode network acknowledges every such FIN; it held core
/// 0 at 100 % in the `storm` smoke (A261-W1).
#[test]
fn fin_wait_2_with_a_half_open_peer_sends_nothing_and_times_out() {
    with_open(
        "
app close
> F. seq=1 ack=1
< . seq=1 ack=2            # our FIN acknowledged; the peer stays open
> nothing
< . seq=1 ack=2            # the peer acknowledges again (a window update, a probe)
> nothing
< . seq=1 ack=2 win=30000
> nothing
+30000
> nothing
expect conns=1
+31000
expect conns=0 closed=timeout
",
    );
}

/// The same with data in flight when the application closes: the FIN rides
/// behind the data, the peer acknowledges both, and nothing follows.
#[test]
fn fin_after_data_is_sent_once() {
    with_open(
        "
app send 24
> P. seq=1 ack=1 len=24
app close
> F. seq=25 ack=1
< . seq=1 ack=26
> nothing
< . seq=1 ack=26
> nothing
+61000
expect conns=0 closed=timeout
",
    );
}

/// Zero window: nothing is sent, the persist timer probes with one byte
/// past the window, backing off, and the probe is sent again as long as
/// the peer does not take it. Data flows once the window opens (RFC 9293
/// §3.8.6.1). Before H3 the second probe sent nothing, so a lost window
/// update stalled the connection for good.
#[test]
fn zero_window_probe_then_resume() {
    with_open(
        "
< . seq=1 ack=1 win=0
app send 100
> nothing
+1000
> P. seq=1 len=1             # the probe: one byte past the closed window
< . seq=1 ack=1 win=0        # still closed, the byte not taken
+1000
> nothing
+1000
> P. seq=1 len=1             # the same byte again, 2 s later (backoff)
< . seq=1 ack=1 win=0
+3000
> nothing
+1000
> P. seq=1 len=1             # 4 s later
< . seq=1 ack=2 win=65535    # open, the probe byte taken
> P. seq=2 len=99
",
    );
}

/// The peer shrinks its window without acknowledging: we never send past
/// the right edge it last advertised (RFC 9293 §3.8.6.2.1).
#[test]
fn shrinking_window_is_respected() {
    with_open(
        "
< . seq=1 ack=1 win=300
app send 1000
> P. seq=1 len=300
> nothing
< . seq=1 ack=1 win=100     # shrunk: no new data, nothing acked
> nothing
< . seq=1 ack=301 win=500
> P. seq=301 len=500
",
    );
}

/// A segment entirely beyond the window, or entirely old, is answered with
/// an ACK and not delivered (RFC 9293 §3.10.7.4).
#[test]
fn out_of_window_segments_get_an_ack() {
    with_open(
        "
< P. seq=100001 ack=1 len=10     # far beyond the window
> . ack=1
expect data=0
< P. seq=1 ack=1 len=10
> . ack=11
< P. seq=1 ack=1 len=10          # an old duplicate
> . ack=11
expect data=10
",
    );
}

/// A retransmission that overlaps data already received delivers only the
/// new bytes.
#[test]
fn overlapping_retransmission_delivers_the_new_part_once() {
    with_open(
        "
< P. seq=1 ack=1 len=100
> . ack=101
< P. seq=51 ack=1 len=100        # bytes 50..150, half of them known
> . ack=151
expect data=150
",
    );
}

/// URG is strict input: MQTT never sends urgent data, and urgent data is
/// a classic way to make two TCP stacks see different streams. A segment
/// with URG is dropped (counted as a bad segment) and nothing is
/// delivered; the connection stays. RFC 9293 §3.8.5 says implementations
/// must support urgent data; this is a deliberate deviation (ADR-055).
#[test]
fn urgent_data_is_dropped() {
    with_open(
        "
< PU. seq=1 ack=1 len=20 urg=5
> nothing
expect data=0 conns=1
< P. seq=1 ack=1 len=20
> . ack=21
expect data=20
",
    );
}

/// Malformed options never crash the parser. An option length of 0 or one
/// running past the header drops the segment (RFC 9293 §3.1: "be prepared
/// to handle an illegal option length"); an MSS option of the wrong length
/// is skipped, so the default MSS of 536 applies.
#[test]
fn malformed_options_are_survived() {
    run("
< S seq=0 opts=02000000          # MSS kind with length 0
> nothing
< S seq=0 opts=0208_05b4         # length past the header
> nothing
< S seq=0 opts=0203_0500         # MSS option of length 3: skipped
> S. ack=1
< S seq=0 opts=01010101_0204_05b4 # NOPs then a good MSS
> S. ack=1 mss=1460
< S seq=0 opts=fe02_0204_05b4    # an unknown option, then MSS
> S. ack=1
");
}

/// MSS extremes: a huge MSS is clamped to ours, and an MSS below 536 is
/// refused (a cookie cannot encode it, and sending 536-byte segments to a
/// peer that asked for less would break RFC 9293 §3.7.1).
#[test]
fn mss_extremes() {
    run("
< S seq=0 mss=65535
> S. ack=1 mss=1460
< S seq=0 mss=100
> nothing
");
}

/// A SYN carrying data: the cookie handshake acknowledges only the SYN; the
/// client retransmits the data after the handshake.
#[test]
fn syn_with_data_acks_only_the_syn() {
    run("
< S seq=0 mss=1460 len=50
> S. ack=1
");
}

/// RFC 5961 §4: a SYN on an established connection gets a challenge ACK
/// and the connection survives.
#[test]
fn syn_on_established_connection_gets_a_challenge_ack() {
    with_open(
        "
< S seq=500 mss=1460
> . ack=1
expect conns=1
",
    );
}

/// RFC 5961 §3: an in-window RST that is not exactly at rcv_nxt gets a
/// challenge ACK; the exact one closes.
#[test]
fn rst_needs_the_exact_sequence_number() {
    with_open(
        "
< R seq=100
> . ack=1
expect conns=1
< R seq=1
> nothing
expect conns=0 closed=reset
",
    );
}

/// RFC 5961 §5: an ACK for data we never sent is dropped with an ACK.
#[test]
fn ack_of_unsent_data_is_refused() {
    with_open(
        "
< P. seq=1 ack=1000 len=10
> . ack=1
expect data=0 conns=1
",
    );
}

/// NOW-19: the MSS follows the link MTU (IPv4: MTU - 40), never above what
/// the stack can send (1460) nor below the IPv4 minimum (536).
#[test]
fn mss_is_derived_from_the_mtu() {
    for (mtu, mss) in [
        (576, 536),
        (1280, 1240),
        (1460, 1420),
        (1500, 1460),
        (9000, 1460),
        (100, 536),
        (0, 536),
        (u16::MAX, 1460),
    ] {
        assert_eq!(mss_for_mtu(mtu), mss, "mtu {mtu}");
    }
    // The cookie table spans exactly that range.
    assert_eq!(cookie::MSS_TABLE[0], MIN_MSS);
    assert_eq!(cookie::MSS_TABLE[7], MAX_MSS);
}

/// NOW-19: for each MTU the SYN-ACK announces MTU - 40 and the data the
/// application sends leaves in segments of at most that much payload: a
/// peer on a 1500-byte network that announces 1460 still gets segments
/// that fit the smaller link.
#[test]
fn segments_fit_the_mtu() {
    for (mtu, mss) in [(576u16, 536u32), (1460, 1420), (1500, 1460), (9000, 1460)] {
        let mut c = cfg();
        c.mss = mss_for_mtu(mtu);
        // 4 KiB: a QoS 1 PUBLISH of the smoke scenario.
        let total = 4096u32;
        let full = total / mss;
        let mut script = format!(
            "
< S seq=0 mss=1460
> S. seq=0 ack=1 mss={mss}
< . seq=1 ack=1
app send {total}
"
        );
        for i in 0..full {
            script.push_str(&format!("> P. seq={} len={mss}\n", 1 + i * mss));
        }
        script.push_str(&format!(
            "> P. seq={} len={}\n> nothing\n< . seq=1 ack={}\nexpect conns=1\n",
            1 + full * mss,
            total - full * mss,
            total + 1
        ));
        run_with(c, &script);
    }
}

/// NOW-19: the smaller of the two MSS values wins (RFC 9293 §3.7.1). A peer
/// with a smaller MSS than ours gets its own; one with a larger gets ours.
/// The SYN-cookie rounds the peer's MSS down to its table (1200 stays 1200).
#[test]
fn the_smaller_mss_wins() {
    let mut c = cfg();
    c.mss = mss_for_mtu(1460);
    run_with(
        c.clone(),
        "
< S seq=0 mss=1200
> S. seq=0 ack=1 mss=1420
< . seq=1 ack=1
app send 2500
> P. seq=1 len=1200
> P. seq=1201 len=1200
> P. seq=2401 len=100
",
    );
    run_with(
        c,
        "
< S seq=0 mss=8960
> S. seq=0 ack=1 mss=1420
< . seq=1 ack=1
app send 2000
> P. seq=1 len=1420
> P. seq=1421 len=580
",
    );
}

/// NOW-19: the MTU drops while a connection is open (a DHCP renewal that
/// announces 1460): the open connection sends no segment larger than the
/// new MSS from then on, retransmissions included, and new connections
/// announce it.
#[test]
fn a_lower_mtu_applies_to_open_connections() {
    with_open(
        "
app send 1460
> P. seq=1 len=1460
app mtu 1460
app send 1500
> P. seq=1461 len=1420
> P. seq=2881 len=80
+1000
> P. seq=1 len=1420            # the timed-out first segment, cut to the new MSS
",
    );
    run_with(
        {
            let mut c = cfg();
            c.mss = 9000; // clamped by the stack: it cannot send more than 1460
            c
        },
        "
< S seq=0 mss=65535
> S. seq=0 ack=1 mss=1460
",
    );
    let mut c = cfg();
    c.mss = 100; // below the IPv4 minimum: clamped up to 536
    run_with(
        c,
        "
< S seq=0 mss=1460
> S. seq=0 ack=1 mss=536
",
    );
}

/// Back-pressure on a publisher (ADR-269): the application closes the
/// receive space. What was promised still arrives and is taken (a window is
/// never retracted), the window then reads 0 and a segment beyond it is not
/// taken; "default" opens the whole window again in one update, never in
/// small steps (no silly-window syndrome).
#[test]
fn the_application_closes_and_reopens_the_window() {
    with_open(
        "
app window 0
> nothing
< P. seq=1 ack=1 len=1000
> . ack=1001 win=64535
< P. seq=1001 ack=1 len=64535
> . ack=65536 win=0
< P. seq=65536 ack=1 len=100     # beyond the closed window: not taken
> . ack=65536 win=0
expect data=65535
app window default
> . ack=65536 win=65535          # one update, the whole window
< P. seq=65536 ack=1 len=100
> . ack=65636 win=65535
expect data=65635
",
    );
}

/// NEXT-1, ADR-330: the scripts that do not depend on the IPv4 MSS run
/// again over IPv6, so the handshake through the cookie, the RFC 5961
/// cases, out-of-window, overlap, urgent data and the close are the same
/// for both families (the checksums use the IPv6 pseudo-header; the
/// SYN-ACK announces 1500 - 60 = 1440).
#[test]
fn the_family_neutral_scripts_hold_over_ipv6() {
    let v6 = |s: &str| s.replace("> S. seq=0 ack=1 mss=1460", "> S. seq=0 ack=1 mss=1440");
    run6(&v6(HANDSHAKE));
    for rest in [
        // RFC 5961 §4, §3, §5.
        "< S seq=500 mss=1460\n> . ack=1\nexpect conns=1\n",
        "< R seq=100\n> . ack=1\nexpect conns=1\n< R seq=1\n> nothing\nexpect conns=0 closed=reset\n",
        "< P. seq=1 ack=1000 len=10\n> . ack=1\nexpect data=0 conns=1\n",
        // Out of window, overlap, urgent data.
        "< P. seq=100001 ack=1 len=10\n> . ack=1\nexpect data=0\n< P. seq=1 ack=1 len=10\n> . ack=11\n",
        "< P. seq=1 ack=1 len=100\n> . ack=101\n< P. seq=51 ack=1 len=100\n> . ack=151\nexpect data=150\n",
        "< PU. seq=1 ack=1 len=20 urg=5\n> nothing\nexpect data=0 conns=1\n",
    ] {
        run6(&format!("{OPEN}{rest}"));
    }
    // The MSS: 1440 announced, a peer's 1460 cut to it, under 536 refused.
    run6("< S seq=0 mss=65535\n> S. ack=1 mss=1440\n< S seq=0 mss=100\n> nothing\n");
}
