#!/usr/bin/env python3
"""X11: turn the raw files of scripts/x11-bench.sh into Markdown tables.

    scripts/x11-report.py docs/perf-results/urmqtt-bench.txt [docs/perf-results/mosquitto.txt ...]

For every run group (same name, several repetitions) it prints the median
and the range (min-max) of the main figures, the generator CPU and the
broker's own busy figure.
"""
import re
import statistics
import sys


def parse(path):
    groups = {}
    order = []
    cur = None
    idle = []
    idle_cur = None
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("RUN "):
                m = re.match(r"RUN (.*) rep=(\d+)", line)
                if m is None:
                    continue
                cur = m.group(1)
                if cur not in groups:
                    groups[cur] = []
                    order.append(cur)
                groups[cur].append({"busy": ""})
                idle_cur = None
            elif line.startswith("RESULT ") and cur:
                kv = dict(x.split("=", 1) for x in line[7:].split() if "=" in x)
                groups[cur][-1].update({k: v for k, v in kv.items()})
            elif line.startswith("HOSTCPU") and cur:
                groups[cur][-1]["host"] = line[len("HOSTCPU"):].strip()
            elif line.startswith("BROKERBUSY") and cur:
                b = line[len("BROKERBUSY"):].strip()
                m = re.match(r"mosquitto_cpu_pct_10s=(\d+)", b)
                if m:
                    # the script prints utime+stime ticks (10 ms) over 10 s
                    b = f"mosquitto {int(m.group(1)) / 10:.0f}% of one core"
                groups[cur][-1]["busy"] = b
            elif line.startswith("IDLE clients="):
                idle_cur = {"clients": int(line.split("=")[1]), "sys": {}, "lines": []}
                idle.append(idle_cur)
                cur = None
            elif line.startswith("IDLE baseline"):
                idle_cur = {"clients": 0, "sys": {}, "lines": []}
                idle.append(idle_cur)
                cur = None
            elif line.startswith("IDLE after close"):
                idle_cur = {"clients": -1, "sys": {}, "lines": []}
                idle.append(idle_cur)
            elif idle_cur is not None:
                if line.startswith("SYS "):
                    k, _, v = line[4:].partition("=")
                    idle_cur["sys"][k] = v
                elif line.startswith("IDLE ") or "hold:" in line:
                    idle_cur["lines"].append(line)
    return groups, order, idle


def stat(vals, fmt="{:.0f}"):
    vals = [float(v) for v in vals if v not in (None, "")]
    if not vals:
        return "-"
    med = statistics.median(vals)
    if len(vals) == 1:
        return fmt.format(med)
    return f"{fmt.format(med)} ({fmt.format(min(vals))}-{fmt.format(max(vals))})"


def main():
    for path in sys.argv[1:]:
        groups, order, idle = parse(path)
        print(f"### {path}\n")
        hs = [g for g in order if g.startswith("handshake")]
        if hs:
            print("| handshake | conn/s | errors | p50 ms | p99 ms | TLS p50 ms | gen cpu | broker busy % (cores, first 14 s) |")
            print("|---|---|---|---|---|---|---|---|")
            for g in hs:
                r = groups[g]
                print(
                    f"| {g.replace('handshake ', '')} | {stat([x.get('conn_per_s') for x in r])} | "
                    f"{stat([x.get('errors') for x in r])} | {stat([x.get('lat_p50_ms') for x in r], '{:.0f}')} | "
                    f"{stat([x.get('lat_p99_ms') for x in r], '{:.0f}')} | {stat([x.get('tls_p50_ms') for x in r], '{:.0f}')} | "
                    f"{stat([x.get('gen_cpu') for x in r], '{:.2f}')} | {r[-1]['busy']} |"
                )
            print()
        for kind in ("throughput", "sweep", "single-flow", "latency", "fanout"):
            gs = [g for g in order if g.startswith(kind)]
            if not gs:
                continue
            print(f"| {kind} | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |")
            print("|---|---|---|---|---|---|---|---|---|---|")
            for g in gs:
                r = groups[g]
                print(
                    f"| {g.replace(kind + ' ', '')} | {stat([x.get('sent_per_s') for x in r])} | "
                    f"{stat([x.get('delivered_per_s') for x in r])} | {stat([x.get('acked_per_s') for x in r])} | "
                    f"{stat([x.get('lat_p50_ms') for x in r], '{:.1f}')} | {stat([x.get('lat_p99_ms') for x in r], '{:.1f}')} | "
                    f"{stat([x.get('lost') for x in r])} | {stat([x.get('gen_cpu') for x in r], '{:.2f}')} | {r[-1]['busy']} | {r[-1].get('host', '')} |"
                )
            print()
        if idle:
            print("| idle connections | broker clients | broker memory (bytes) | detail |")
            print("|---|---|---|---|")
            for i in idle:
                s = i["sys"]
                mem = s.get("$SYS/broker/memory/used") or s.get("$SYS/broker/heap/current") or "-"
                cl = s.get("$SYS/broker/clients/connected", "-")
                name = {0: "baseline", -1: "after close"}.get(i["clients"], str(i["clients"]))
                print(f"| {name} | {cl} | {mem} | {'; '.join(i['lines'])[:160]} {s.get('rss_kb', '')} |")
            print()


main()
