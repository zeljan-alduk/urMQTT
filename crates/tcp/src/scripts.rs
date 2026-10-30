//! H3: scripted TCP edge cases (RFC 9293, RFC 5961), see `script.rs` for
//! the language. Each script states what the stack must do, segment by
//! segment.

use alloc::format;

use crate::script::run;

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
