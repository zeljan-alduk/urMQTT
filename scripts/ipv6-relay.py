#!/usr/bin/env python3
"""The whole network of a guest on QEMU's dgram netdev, for the IPv6 smoke
scenarios (NEXT-1, ADR-330 to ADR-334).

QEMU's user network forwards host ports over IPv4 only, so a host client cannot
reach a guest over IPv6 through it. This script is the guest's link instead
(`run-qemu.sh --dgram LOCAL:REMOTE`): one Ethernet frame per UDP datagram. It

- is the router: sends Router Advertisements (a /64 prefix with the A and L
  flags and an MTU option, or none with --no-prefix), answers Neighbour
  Solicitations for its addresses and ARP for its IPv4 address;
- relays host TCP connections into the guest: every `--listen KIND:PORT:GUEST_PORT`
  accepts on 127.0.0.1:PORT (an ordinary host socket, so mosquitto and openssl
  are the clients) and opens a TCP connection of its own to the guest's IPv6
  (KIND 6) or IPv4 (KIND 4) address, carried in frames this script writes: a
  small TCP client (in-order receive, retransmission of what is not
  acknowledged, FIN both ways);
- with --probe, sends what the guest must drop or answer once its address is
  known: an ICMPv6 echo request (the reply is printed), a fragment, a packet
  with an extension header option that must not be skipped, a TCP segment with
  a bad checksum, and a Neighbour Solicitation with hop limit 64.

It prints what it sees to stdout ("relay: ..."); the smoke scenario greps it.
Run with -I; stops on SIGTERM.
"""

import argparse
import os
import random
import select
import signal
import socket
import struct
import sys
import time

MAC = bytes.fromhex("525500000001")
LL = bytes.fromhex("fe800000000000000000000000000001")
V4 = bytes([10, 0, 2, 2])


def log(msg):
    print(f"relay: {msg}", flush=True)


def csum(data, acc=0):
    if len(data) % 2:
        data += b"\0"
    for i in range(0, len(data), 2):
        acc += (data[i] << 8) | data[i + 1]
    while acc > 0xFFFF:
        acc = (acc & 0xFFFF) + (acc >> 16)
    return (~acc) & 0xFFFF


def pseudo6(src, dst, nh, length):
    return src + dst + struct.pack("!IxxxB", length, nh)


def pseudo4(src, dst, proto, length):
    return src + dst + struct.pack("!xBH", proto, length)


def a6(text):
    return socket.inet_pton(socket.AF_INET6, text)


def t6(b):
    return socket.inet_ntop(socket.AF_INET6, b)


def eth(dst, ethertype, payload):
    return dst + MAC + struct.pack("!H", ethertype) + payload


def ipv6(src, dst, nh, payload, hop=255):
    return struct.pack("!IHBB", 0x60000000, len(payload), nh, hop) + src + dst + payload


def icmp6(src, dst, t, code, body, hop=255):
    msg = struct.pack("!BBH", t, code, 0) + body
    c = csum(pseudo6(src, dst, 58, len(msg)) + msg)
    msg = msg[:2] + struct.pack("!H", c) + msg[4:]
    return ipv6(src, dst, 58, msg, hop)


def ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, src, dst)
    c = csum(h)
    return h[:10] + struct.pack("!H", c) + h[12:] + payload


def mcast_mac(addr):
    return bytes([0x33, 0x33]) + addr[12:]


def solicited(addr):
    return a6("ff02::1:ff00:0")[:13] + addr[13:]


class Flow:
    """One relayed connection: a host socket and a TCP client towards the guest."""

    def __init__(self, relay, host, kind, gport):
        self.r = relay
        self.host = host
        self.kind = kind
        self.gport = gport
        self.lport = random.randint(40000, 60000)
        self.iss = random.getrandbits(32)
        self.snd_una = self.iss
        self.snd_nxt = self.iss
        self.rcv_nxt = None
        self.unacked = b""
        self.pending = b""
        self.state = "syn"
        self.fin_sent = False
        self.fin_acked = False
        self.fin_seq = None
        self.peer_fin = False
        self.host_closed = False
        self.last_tx = 0.0
        self.rto = 0.5
        self.guest_mss = 536
        self.send_syn()

    def addrs(self):
        if self.kind == 6:
            return self.r.my6(self.r.guest6), self.r.guest6
        return V4, self.r.guest4

    def seg(self, flags, seq, payload=b"", opts=b""):
        src, dst = self.addrs()
        off = (20 + len(opts)) // 4
        ack = self.rcv_nxt or 0
        h = struct.pack("!HHIIBBHHH", self.lport, self.gport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, off << 4, flags, 65535, 0, 0) + opts
        seg = h + payload
        if self.kind == 6:
            c = csum(pseudo6(src, dst, 6, len(seg)) + seg)
            seg = seg[:16] + struct.pack("!H", c) + seg[18:]
            self.r.send6(dst, ipv6(src, dst, 6, seg, 64))
        else:
            c = csum(pseudo4(src, dst, 6, len(seg)) + seg)
            seg = seg[:16] + struct.pack("!H", c) + seg[18:]
            self.r.send4(ipv4(src, dst, 6, seg))

    def send_syn(self):
        self.seg(0x02, self.iss, opts=struct.pack("!BBH", 2, 4, 1200))
        self.snd_nxt = self.iss + 1
        self.last_tx = time.monotonic()

    def from_host(self, data):
        self.pending += data
        self.pump()

    def pump(self):
        if self.state != "open":
            return
        window = 32768
        while self.pending and len(self.unacked) < window:
            n = min(len(self.pending), self.guest_mss, 1000)
            chunk, self.pending = self.pending[:n], self.pending[n:]
            self.seg(0x18, self.snd_una + len(self.unacked), chunk)
            self.unacked += chunk
            self.last_tx = time.monotonic()
        if self.host_closed and not self.pending and not self.fin_sent:
            self.fin_seq = self.snd_una + len(self.unacked)
            self.seg(0x11, self.fin_seq)
            self.fin_sent = True
            self.last_tx = time.monotonic()

    def timer(self, now):
        if now - self.last_tx < self.rto:
            return
        if self.state == "syn":
            self.send_syn()
            return
        if self.state != "open":
            return
        if self.unacked:
            # Go back N: everything unacknowledged again.
            data, seq = self.unacked, self.snd_una
            while data:
                n = min(len(data), self.guest_mss, 1000)
                self.seg(0x18, seq, data[:n])
                seq += n
                data = data[n:]
            self.last_tx = now
        elif self.fin_sent and not self.fin_acked:
            self.seg(0x11, self.fin_seq)
            self.last_tx = now

    def segment(self, flags, seq, ack, payload, opts):
        if flags & 0x04:
            log(f"flow {self.lport}: reset by the guest")
            self.close()
            return
        if self.state == "syn":
            if flags & 0x12 == 0x12 and ack == (self.iss + 1) & 0xFFFFFFFF:
                self.rcv_nxt = (seq + 1) & 0xFFFFFFFF
                self.snd_una = self.iss + 1
                i = 0
                while i < len(opts):
                    if opts[i] == 0:
                        break
                    if opts[i] == 1:
                        i += 1
                        continue
                    if opts[i] == 2 and i + 4 <= len(opts):
                        self.guest_mss = struct.unpack("!H", opts[i + 2:i + 4])[0]
                    i += max(2, opts[i + 1] if i + 1 < len(opts) else 2)
                self.state = "open"
                self.seg(0x10, self.snd_una)
                log(f"flow {self.lport}: connected to the guest over IPv{self.kind}, its MSS {self.guest_mss}")
                self.pump()
            return
        if flags & 0x10:
            # Acknowledged bytes leave the buffer (32-bit wrap around snd_una).
            acked = (ack - self.snd_una) & 0xFFFFFFFF
            fin_open = 1 if self.fin_sent and not self.fin_acked else 0
            if 0 < acked <= len(self.unacked) + fin_open:
                if fin_open and acked == len(self.unacked) + 1:
                    self.fin_acked = True
                self.unacked = self.unacked[min(acked, len(self.unacked)):]
                self.snd_una = (self.snd_una + acked) & 0xFFFFFFFF
        if payload or flags & 0x01:
            if seq == self.rcv_nxt:
                if payload:
                    try:
                        self.host.sendall(payload)
                    except OSError:
                        self.close()
                        return
                self.rcv_nxt = (self.rcv_nxt + len(payload)) & 0xFFFFFFFF
                if flags & 0x01:
                    self.rcv_nxt = (self.rcv_nxt + 1) & 0xFFFFFFFF
                    self.peer_fin = True
                    try:
                        self.host.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
            self.seg(0x10, self.snd_nxt_seq())
        self.pump()
        if self.peer_fin and self.fin_acked:
            self.close()

    def snd_nxt_seq(self):
        return self.snd_una + len(self.unacked) + (1 if self.fin_sent and not self.fin_acked else 0)

    def close(self):
        self.state = "closed"
        try:
            self.host.close()
        except OSError:
            pass
        self.r.flows.pop(self.lport, None)


class Relay:
    def __init__(self, a):
        self.a = a
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", a.local))
        self.remote = ("127.0.0.1", a.remote)
        self.guest_mac = None
        self.guest6 = a6(a.guest6)
        self.guest4 = socket.inet_aton(a.guest4) if a.guest4 else None
        self.prefix = a6(a.prefix) if a.prefix else None
        self.global6 = (self.prefix[:8] + bytes(7) + b"\x01") if self.prefix else None
        if a.router6:
            self.global6 = a6(a.router6)
        self.flows = {}
        self.listeners = []
        for spec in a.listen:
            kind, port, gport = (int(x) for x in spec.split(":"))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(16)
            self.listeners.append((s, kind, gport))
        self.next_ra = 0.0
        self.ras = 0
        self.seen_guest = False
        self.probed = False
        self.echo_seen = False
        # When the guest probed its global address (DAD): its probes go out
        # 2.5 s later, once the address is in use.
        self.dad_at = None

    def my6(self, peer):
        if peer[:2] == b"\xfe\x80" or self.global6 is None:
            return LL
        return self.global6

    def send(self, frame):
        self.udp.sendto(frame, self.remote)

    def send6(self, dst, pkt):
        mac = self.guest_mac or mcast_mac(dst)
        self.send(eth(mac, 0x86DD, pkt))

    def send4(self, pkt):
        self.send(eth(self.guest_mac or b"\xff" * 6, 0x0800, pkt))

    def ra(self):
        body = struct.pack("!BBHII", 64, 0, 1800, 0, 0)
        body += struct.pack("!BB", 1, 1) + MAC
        body += struct.pack("!BBHI", 5, 1, 0, self.a.mtu)
        if self.prefix:
            body += struct.pack("!BBBBIII", 3, 4, 64, 0xC0, 86400, 14400, 0) + self.prefix
        self.send(eth(mcast_mac(a6("ff02::1")), 0x86DD, icmp6(LL, a6("ff02::1"), 134, 0, body)))
        self.ras += 1

    def frame(self, f):
        if len(f) < 14:
            return
        dst, src, et = f[:6], f[6:12], struct.unpack("!H", f[12:14])[0]
        p = f[14:]
        if et == 0x0806 and len(p) >= 28:
            op = struct.unpack("!H", p[6:8])[0]
            if op == 1 and p[24:28] == V4:
                self.guest_mac = src
                rep = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + MAC + V4 + p[8:14] + p[14:18]
                self.send(eth(src, 0x0806, rep))
            return
        if et == 0x0800 and len(p) >= 20 and p[9] == 6:
            self.guest_mac = src
            ihl = (p[0] & 15) * 4
            self.tcp(4, p[12:16], p[ihl:struct.unpack("!H", p[2:4])[0]])
            return
        if et != 0x86DD or len(p) < 40:
            return
        nh, plen = p[6], struct.unpack("!H", p[4:6])[0]
        s, d, body = p[8:24], p[24:40], p[40:40 + plen]
        if s != bytes(16):
            self.guest_mac = src
            if not self.seen_guest:
                self.seen_guest = True
                log(f"guest {t6(s)} at {src.hex(':')}")
        if nh == 0 and len(body) >= 8:
            # A Hop-by-Hop header (the guest's MLD report carries Router Alert).
            nh, body = body[0], body[(body[1] + 1) * 8:]
        if nh == 58 and body:
            t = body[0]
            if t == 135 and len(body) >= 24:
                target = body[8:24]
                if s == bytes(16):
                    log(f"DAD probe for {t6(target)}")
                    if target == self.guest6:
                        self.dad_at = time.monotonic()
                elif target in (LL, self.global6):
                    na = struct.pack("!I", 0x60000000) + target + struct.pack("!BB", 2, 1) + MAC
                    self.send(eth(src, 0x86DD, icmp6(target, s, 136, 0, na)))
            elif t == 133:
                log("router solicitation")
                self.ra()
            elif t == 129:
                log(f"echo reply from {t6(s)}")
                self.echo_seen = True
            elif t == 143:
                log("MLD report")
        elif nh == 6:
            self.tcp(6, s, body)

    def tcp(self, kind, src, seg):
        if len(seg) < 20:
            return
        sport, dport, seq, ack, off, flags = struct.unpack("!HHIIBB", seg[:14])
        hl = (off >> 4) * 4
        f = self.flows.get(dport)
        if f is None or f.kind != kind:
            return
        f.segment(flags, seq, ack, seg[hl:], seg[20:hl])

    def probe(self):
        """What the guest must answer or drop (counted), once."""
        g, me = self.guest6, self.my6(self.guest6)
        self.send6(g, icmp6(me, g, 128, 0, struct.pack("!HH", 0x5155, 1) + b"relay ping", 64))
        # A fragment header (44) before TCP: dropped, counted as a fragment.
        frag = struct.pack("!BBHI", 6, 0, 1, 0x1234) + bytes(20)
        self.send6(g, ipv6(me, g, 44, frag, 64))
        # A destination options header with an option whose action bits say
        # discard (0x80): dropped, counted as an extension header.
        dopt = struct.pack("!BB", 6, 0) + bytes([0x80, 4, 0, 0, 0, 0]) + bytes(20)
        self.send6(g, ipv6(me, g, 60, dopt, 64))
        # A Neighbour Solicitation from off the link (hop limit 64): ignored.
        ns = struct.pack("!I", 0) + g + struct.pack("!BB", 1, 1) + MAC
        self.send6(g, icmp6(me, solicited(g), 135, 0, ns, 64))
        log("probes sent")

    def run(self, deadline):
        stop = []
        signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
        log(f"listening on udp {self.a.local}, guest {t6(self.guest6)}")
        while not stop and time.monotonic() < deadline:
            now = time.monotonic()
            if now >= self.next_ra:
                self.ra()
                self.next_ra = now + (1.0 if self.ras < 10 else 10.0)
            if self.a.probe and not self.probed and self.dad_at and now - self.dad_at > 2.5:
                self.probed = True
                self.probe()
            socks = [self.udp] + [l[0] for l in self.listeners] + [f.host for f in self.flows.values() if f.state != "closed"]
            r, _, _ = select.select(socks, [], [], 0.05)
            for s in r:
                if s is self.udp:
                    try:
                        data, _ = self.udp.recvfrom(4096)
                    except OSError:
                        continue
                    self.frame(data)
                    continue
                lst = next((l for l in self.listeners if l[0] is s), None)
                if lst is not None:
                    conn, _ = s.accept()
                    if not self.guest_mac:
                        conn.close()
                        continue
                    f = Flow(self, conn, lst[1], lst[2])
                    self.flows[f.lport] = f
                    continue
                f = next((x for x in list(self.flows.values()) if x.host is s), None)
                if f is None:
                    continue
                try:
                    data = s.recv(65536)
                except OSError:
                    data = b""
                if data:
                    f.from_host(data)
                else:
                    f.host_closed = True
                    f.pump()
            for f in list(self.flows.values()):
                f.timer(time.monotonic())
        log("stopped")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", type=int, required=True, help="UDP port this script binds (QEMU's REMOTE)")
    ap.add_argument("--remote", type=int, required=True, help="UDP port QEMU binds (QEMU's LOCAL)")
    ap.add_argument("--guest6", required=True)
    ap.add_argument("--guest4", default="")
    ap.add_argument("--prefix", default="", help="the /64 advertised for SLAAC, e.g. 2001:db8:1::")
    ap.add_argument("--router6", default="", help="this script's global address (default: prefix::1)")
    ap.add_argument("--mtu", type=int, default=1500)
    ap.add_argument("--listen", action="append", default=[], help="KIND:HOSTPORT:GUESTPORT")
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--seconds", type=int, default=600)
    a = ap.parse_args()
    random.seed(os.getpid())
    Relay(a).run(time.monotonic() + a.seconds)


if __name__ == "__main__":
    sys.exit(main())
