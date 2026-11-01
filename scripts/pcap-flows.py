#!/usr/bin/env python3
"""Per-flow TCP dynamics from a pcap of a benchmark run (PERF, ADR-233).

    pcap-flows.py FILE.pcap [SERVER_PORT [SERVER_IP]]

Reads a classic pcap (Ethernet, Linux cooked v1/v2, raw IP; microsecond or
nanosecond stamps) captured on the load generator host, and prints for every TCP flow
of the server port (default 8883), for each direction: payload bytes and segments,
retransmissions (a segment below the highest sequence sent), the data bytes in
flight, the window the receiver advertised, how many data segments one
acknowledgement covers and how far apart the acknowledgements are, SACK blocks, gaps
without data longer than 20 ms, and round trip samples from the timestamp option.
Only Python's standard library; meant to be run on the Mac, not on the shared host.
"""
import struct
import sys
from collections import defaultdict


def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
    else:
        raise SystemExit("not a classic pcap file")
    _, _, _, _, _, link = struct.unpack(end + "HHiIII", data[4:24])
    pos = 24
    scale = 1e-9 if nano else 1e-6
    while pos + 16 <= len(data):
        sec, frac, caplen, _ = struct.unpack(end + "IIII", data[pos:pos + 16])
        pos += 16
        pkt = data[pos:pos + caplen]
        pos += caplen
        yield sec + frac * scale, link, pkt


def ip_of(link, pkt):
    if link == 1:  # Ethernet (skip VLAN tags)
        off, et = 14, struct.unpack(">H", pkt[12:14])[0]
        while et in (0x8100, 0x88A8) and len(pkt) >= off + 4:
            et = struct.unpack(">H", pkt[off + 2:off + 4])[0]
            off += 4
        return pkt[off:] if et == 0x0800 else None
    if link == 113:  # Linux cooked v1
        return pkt[16:] if struct.unpack(">H", pkt[14:16])[0] == 0x0800 else None
    if link == 276:  # Linux cooked v2
        return pkt[20:] if struct.unpack(">H", pkt[0:2])[0] == 0x0800 else None
    if link in (12, 101):
        return pkt
    return None


def tcp_of(ip):
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 15) * 4
    total = struct.unpack(">H", ip[2:4])[0]
    src, dst = ip[12:16], ip[16:20]
    t = ip[ihl:total] if total else ip[ihl:]
    if len(t) < 20:
        return None
    sport, dport, seq, ack, off, flags, win = struct.unpack(">HHIIBBH", t[:16])
    doff = (off >> 4) * 4
    opts = t[20:doff]
    payload = max(0, len(t) - doff)
    # the capture may be cut short (snaplen): the IP header knows the real length
    payload = max(0, total - ihl - doff) if total else payload
    tsval = tsecr = None
    sack = 0
    wscale = None
    i = 0
    while i < len(opts):
        k = opts[i]
        if k == 0:
            break
        if k == 1:
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        n = opts[i + 1]
        if n < 2:
            break
        body = opts[i + 2:i + n]
        if k == 8 and len(body) == 8:
            tsval, tsecr = struct.unpack(">II", body)
        elif k == 5:
            sack = len(body) // 8
        elif k == 3 and body:
            wscale = body[0]
        i += n
    return dict(src=src, dst=dst, sport=sport, dport=dport, seq=seq, ack=ack, flags=flags,
                win=win, payload=payload, tsval=tsval, tsecr=tsecr, sack=sack, wscale=wscale)


def dot(b):
    return ".".join(str(x) for x in b)


def pct(v, p):
    if not v:
        return 0
    v = sorted(v)
    return v[min(len(v) - 1, int(len(v) * p / 100))]


def main():
    path = sys.argv[1]
    sport = int(sys.argv[2]) if len(sys.argv) > 2 else 8883
    server_ip = sys.argv[3] if len(sys.argv) > 3 else None
    flows = defaultdict(list)
    t0 = None
    for ts, link, pkt in read_pcap(path):
        ip = ip_of(link, pkt)
        if ip is None:
            continue
        s = tcp_of(ip)
        if s is None:
            continue
        if s["sport"] == sport:
            key, d = (dot(s["dst"]), s["dport"]), "S2C"
        elif s["dport"] == sport:
            key, d = (dot(s["src"]), s["sport"]), "C2S"
        else:
            continue
        if server_ip and dot(s["src"] if d == "S2C" else s["dst"]) != server_ip:
            continue
        if t0 is None:
            t0 = ts
        flows[key].append((ts - t0, d, s))
    if not flows:
        print("no flows of port", sport)
        return
    span = max(p[0] for f in flows.values() for p in f)
    print(f"capture: {sum(len(f) for f in flows.values())} TCP segments, {span:.2f} s, {len(flows)} flow(s)")
    for key, segs in sorted(flows.items(), key=lambda kv: -sum(p[2]["payload"] for p in kv[1])):
        tot = {"C2S": 0, "S2C": 0}
        for _, d, s in segs:
            tot[d] += s["payload"]
        if tot["C2S"] + tot["S2C"] < 100000:
            continue
        print(f"\nflow {key[0]}:{key[1]}  client->server {tot['C2S'] / 1e6:.2f} MB, server->client {tot['S2C'] / 1e6:.2f} MB")
        shift = {"C2S": None, "S2C": None}  # window scale announced by the SENDER of the SYN/SYN-ACK
        for _, d, s in segs:
            if s["flags"] & 2 and s["wscale"] is not None:
                shift[d] = s["wscale"]
        for data_dir in ("C2S", "S2C"):
            if tot[data_dir] < 50000:
                continue
            ack_dir = "S2C" if data_dir == "C2S" else "C2S"
            # data_dir carries the stream; ack_dir acknowledges it
            maxseq = None
            base = None
            retx = 0
            nseg = 0
            gaps = []
            last_data_t = None
            inflight = []
            una = None
            wins = []
            acks = []  # (t, ackno)
            sacks = 0
            dupacks = 0
            last_ack = None
            seg_times = {}
            rtts = []
            ts_sent = {}
            bytes_per_ack = []
            segs_since_ack = 0
            ack_gaps = []
            last_ack_t = None
            highest = None
            seen_seq = {}
            retx_seen = 0
            bursts = []
            cur_burst = 0
            last_burst_t = None
            for t, d, s in segs:
                if d == data_dir and s["payload"] > 0:
                    nseg += 1
                    end = (s["seq"] + s["payload"]) & 0xFFFFFFFF
                    if base is None:
                        base = s["seq"]
                    if highest is None or ((end - highest) & 0xFFFFFFFF) < 0x80000000 and end != highest:
                        highest = end
                    else:
                        retx += 1
                        if s["seq"] in seen_seq:
                            retx_seen += 1
                    seen_seq.setdefault(s["seq"], t)
                    if last_data_t is not None and t - last_data_t > 0.02:
                        gaps.append(t - last_data_t)
                    last_data_t = t
                    segs_since_ack += 1
                    if s["tsval"] is not None:
                        ts_sent.setdefault(s["tsval"], t)
                    if last_burst_t is not None and t - last_burst_t < 0.0005:
                        cur_burst += 1
                    else:
                        if cur_burst:
                            bursts.append(cur_burst)
                        cur_burst = 1
                    last_burst_t = t
                elif d == ack_dir and s["flags"] & 16:
                    ackno = s["ack"]
                    if una is not None and ackno == una and s["payload"] == 0:
                        dupacks += 1
                    if una is None or ((ackno - una) & 0xFFFFFFFF) < 0x80000000:
                        if una is not None and ackno != una:
                            bytes_per_ack.append((ackno - una) & 0xFFFFFFFF)
                            if last_ack_t is not None:
                                ack_gaps.append(t - last_ack_t)
                            last_ack_t = t
                            segs_since_ack = 0
                        una = ackno
                    if s["sack"]:
                        sacks += 1
                    sh = shift.get(data_dir if False else ack_dir)
                    wins.append(s["win"] << (sh or 0))
                    if highest is not None and una is not None:
                        inflight.append(((highest - una) & 0xFFFFFFFF) if ((highest - una) & 0xFFFFFFFF) < 0x80000000 else 0)
                    if s["tsecr"] in ts_sent:
                        rtts.append((t - ts_sent.pop(s["tsecr"])) * 1000)
            label = "generator -> broker (publisher leg)" if data_dir == "C2S" else "broker -> generator (subscriber leg)"
            print(f"  {label}: {tot[data_dir] / 1e6:.2f} MB in {nseg} segments (mean {tot[data_dir] / max(nseg, 1):.0f} B), "
                  f"{retx} retransmitted ({100.0 * retx / max(nseg, 1):.2f} %; {retx_seen} of them already seen in this capture), "
                  f"dup ACKs {dupacks}, ACKs with SACK {sacks}")
            if inflight:
                print(f"    in flight (bytes): median {pct(inflight, 50)}, p90 {pct(inflight, 90)}, max {max(inflight)}; "
                      f"receiver window: median {pct(wins, 50)}, min {min(wins)}")
            if bytes_per_ack:
                print(f"    one ACK covers (bytes): median {pct(bytes_per_ack, 50)}, p90 {pct(bytes_per_ack, 90)}, max {max(bytes_per_ack)}; "
                      f"ACK spacing (ms): median {pct(ack_gaps, 50) * 1000:.2f}, p90 {pct(ack_gaps, 90) * 1000:.2f}")
            if rtts:
                print(f"    round trip from the timestamps (ms): median {pct(rtts, 50):.1f}, p90 {pct(rtts, 90):.1f}, max {max(rtts):.1f}")
            if bursts:
                print(f"    back-to-back segments (gap < 0.5 ms): median {pct(bursts, 50)}, p90 {pct(bursts, 90)}, max {max(bursts)}")
            print(f"    pauses of more than 20 ms without data: {len(gaps)}, together {sum(gaps):.2f} s of {span:.1f} s"
                  + (f", longest {max(gaps) * 1000:.0f} ms" if gaps else ""))


if __name__ == "__main__":
    main()
