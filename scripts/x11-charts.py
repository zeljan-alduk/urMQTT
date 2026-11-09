#!/usr/bin/env python3
"""X11: the comparison figures from the raw files of scripts/x11-bench.sh.

    uv run --no-project --with matplotlib python3 scripts/x11-charts.py OUTDIR \
        "VPS/Broker=path/to/results.txt" [...]

VPS and broker names are free text; brokers are drawn in the order first seen,
with one fixed colour each across every figure. Each figure puts the VPSes side
by side (shared y-axis) so that a bar or a line means the same thing in both
panels. Bars are the median of the repetitions with a min-max range; lines
carry their value at the end. Writes PNG (2x) and SVG.
"""
import re
import statistics
import sys
from collections import OrderedDict, defaultdict

import matplotlib
import matplotlib.ticker as mticker

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# The validated default palette of the dataviz skill (light surface).
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
SURFACE, INK, INK2, INK3, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#8a8984", "#e9e8e3"
plt.rcParams.update({
    "font.family": ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"],
    "font.size": 9,
    "axes.titlesize": 10,
    "axes.titleweight": "semibold",
    "axes.labelcolor": INK2,
    "xtick.color": INK2,
    "ytick.color": INK2,
    "axes.edgecolor": GRID,
    "svg.fonttype": "none",
})


def parse(path):
    """-> ({run name: [ {k: v} per repetition ]}, idle rows)."""
    groups, cur, idle, idle_cur = OrderedDict(), None, [], None
    for line in open(path):
        line = line.rstrip("\n")
        if line.startswith("RUN "):
            m = re.match(r"RUN (.*) rep=(\d+)", line)
            if not m:
                continue
            cur = m.group(1)
            groups.setdefault(cur, []).append({})
            idle_cur = None
        elif line.startswith("RESULT ") and cur:
            groups[cur][-1].update(dict(x.split("=", 1) for x in line[7:].split() if "=" in x))
        elif line.startswith("BROKERBUSY") and cur:
            b = line[len("BROKERBUSY"):].strip()
            m = re.match(r"mosquitto_cpu_pct_10s=(\d+)", b)
            if m:
                groups[cur][-1]["busy_cores"] = int(m.group(1)) / 1000
            else:
                cores = [float(v) for v in re.findall(r"c\d+=(\d+)", b)]
                if cores:
                    groups[cur][-1]["busy_cores"] = sum(cores) / 100
        elif line.startswith("IDLE clients="):
            idle_cur = {"clients": int(line.split("=")[1].split()[0]), "sys": {}}
            idle.append(idle_cur)
            cur = None
        elif line.startswith("IDLE baseline"):
            idle_cur = {"clients": 0, "sys": {}}
            idle.append(idle_cur)
            cur = None
        elif line.startswith("IDLE after close"):
            idle_cur = None
        elif idle_cur is not None and line.startswith("SYS "):
            k, _, v = line[4:].partition("=")
            idle_cur["sys"][k.strip()] = v.strip()
    return groups, idle


def stat(reps, key, scale=1.0):
    vals = [float(r[key]) * scale for r in (reps or []) if r.get(key) not in (None, "")]
    return (statistics.median(vals), min(vals), max(vals)) if vals else None


def find(groups, pattern):
    for name, reps in groups.items():
        if re.fullmatch(pattern, name):
            return reps
    return None


def idle_memory(idle, clients):
    for row in idle:
        if row["clients"] == clients:
            s = row["sys"]
            if "$SYS/broker/memory/used" in s:
                return float(s["$SYS/broker/memory/used"])
            if "rss_kb" in s:
                return float(s["rss_kb"]) * 1024
    return None


def fmt(v):
    if v >= 10000:
        return f"{v / 1000:,.0f}k"
    if v >= 100:
        return f"{v:,.0f}"
    return f"{v:.1f}" if v < 10 else f"{v:.0f}"


class Figure:
    def __init__(self, vpses, title, subtitle, height=4.4):
        self.fig, self.axes = plt.subplots(1, len(vpses), figsize=(12.5, height), dpi=200, sharey=True)
        if len(vpses) == 1:
            self.axes = [self.axes]
        self.fig.patch.set_facecolor(SURFACE)
        self.fig.text(0.012, 0.975, title, fontsize=13, fontweight="semibold", color=INK, va="top")
        self.fig.text(0.012, 0.925, subtitle, fontsize=8.5, color=INK2, va="top")
        for ax, vps in zip(self.axes, vpses):
            ax.set_facecolor(SURFACE)
            ax.set_title(vps, loc="left", color=INK, pad=8)
            ax.yaxis.grid(True, color=GRID, lw=0.8)
            ax.set_axisbelow(True)
            for s in ("top", "right", "left"):
                ax.spines[s].set_visible(False)
            ax.tick_params(which="both", length=0)

    def legend(self, handle_lists, order):
        seen = {}
        for hs in handle_lists:
            for h in hs:
                seen.setdefault(h.get_label(), h)
        labels = [b for b in order if b in seen]
        self.fig.legend([seen[b] for b in labels], labels, loc="upper right", bbox_to_anchor=(0.99, 0.99),
                        frameon=False, fontsize=8.5, ncol=len(labels), handlelength=1.2)

    def fit_y(self, log=False):
        top = 0
        for ax in self.axes:
            for line in ax.get_lines():
                ys = [y for y in line.get_ydata() if y == y]
                top = max(top, max(ys, default=0))
            for coll in ax.collections:
                try:
                    top = max(top, coll.get_paths()[0].vertices[:, 1].max())
                except (IndexError, AttributeError):
                    pass
            for patch in ax.patches:
                top = max(top, patch.get_y() + patch.get_height())
            for txt in ax.texts:
                top = max(top, txt.get_position()[1])
        if top > 0:
            self.axes[0].set_ylim(0.5 if log else 0, top * (1.9 if log else 1.12))

    def save(self, outdir, name, footer):
        self.fig.text(0.012, 0.012, footer, fontsize=7, color=INK3)
        self.fig.tight_layout(rect=(0, 0.03, 1, 0.9))
        for ext in ("png", "svg"):
            self.fig.savefig(f"{outdir}/{name}.{ext}", facecolor=SURFACE)
        plt.close(self.fig)
        print(f"{outdir}/{name}.png")


def bars(ax, brokers, specs, colors, scale=1.0, whisker="range"):
    """Grouped bars: one group per spec, one bar per broker. Returns legend handles."""
    n = len(brokers)
    width = 0.78 / n
    handles = []
    for bi, (label, (groups, _)) in enumerate(brokers.items()):
        xs, ys, lo, hi = [], [], [], []
        for i, (_, pat, key) in enumerate(specs):
            reps = find(groups, pat)
            s = stat(reps, key, scale)
            if s is None:
                continue
            if whisker == "p99":
                p99 = stat(reps, "lat_p99_ms")
                s = (s[0], s[0], p99[0]) if p99 else s
            xs.append(i + (bi - (n - 1) / 2) * width)
            ys.append(s[0])
            lo.append(s[0] - s[1])
            hi.append(s[2] - s[0])
        h = ax.bar(xs, ys, width * 0.9, color=colors[label], zorder=3, label=label)
        handles.append(h)
        ax.errorbar(xs, ys, yerr=[lo, hi], fmt="none", ecolor=INK3, elinewidth=0.9, capsize=2, zorder=4)
        for x, y, hh in zip(xs, ys, hi):
            ax.text(x, y + hh, fmt(y), ha="center", va="bottom", fontsize=6.8, color=INK, zorder=5)
    ax.set_xticks(range(len(specs)))
    ax.set_xticklabels([s[0] for s in specs], fontsize=8)
    return handles


def lines(ax, brokers, xs_spec, key, colors, scale=1.0, label_last=True):
    """One line per broker over the x values of xs_spec = [(x, run regex)]."""
    handles = []
    for label, (groups, _) in brokers.items():
        pts = []
        for x, pat in xs_spec:
            s = stat(find(groups, pat), key, scale)
            if s:
                pts.append((x, s[0], s[1], s[2]))
        if not pts:
            continue
        px = [p[0] for p in pts]
        py = [p[1] for p in pts]
        ax.fill_between(px, [p[2] for p in pts], [p[3] for p in pts], color=colors[label], alpha=0.12, lw=0)
        (h,) = ax.plot(px, py, "-o", color=colors[label], lw=2, ms=5, label=label, zorder=3)
        handles.append(h)
        if label_last:
            ax.annotate(fmt(py[-1]), (px[-1], py[-1]), xytext=(5, 0), textcoords="offset points", va="center",
                        fontsize=7.5, color=INK)
    return handles


THREADS = [(32, r"handshake threads=32"), (64, r"handshake threads=64"), (128, r"handshake threads=128")]
SWEEP0 = [(1600, r"sweep qos=0 payload=64 rate=100 pairs=16"), (4800, r"sweep qos=0 payload=64 rate=300 pairs=16"),
          (16000, r"sweep qos=0 payload=64 rate=1000 pairs=16")]
SWEEP1 = [(1600, r"sweep qos=1 payload=64 rate=100 pairs=16"), (4800, r"sweep qos=1 payload=64 rate=300 pairs=16"),
          (16000, r"sweep qos=1 payload=64 rate=1000 pairs=16")]
FLOOD = [("16 pairs\nQoS 0, 64 B", r"throughput qos=0 payload=64 pairs=16", "delivered_per_s"),
         ("16 pairs\nQoS 0, 1 KiB", r"throughput qos=0 payload=1024 pairs=16", "delivered_per_s"),
         ("16 pairs\nQoS 1, 64 B", r"throughput qos=1 payload=64 pairs=16", "delivered_per_s"),
         ("64 pairs\nQoS 1, 64 B", r"throughput qos=1 payload=64 pairs=64", "delivered_per_s"),
         ("fan-out 1→100\nQoS 0", r"fanout qos=0 subs=100 rate=0", "delivered_per_s")]
SINGLE = [("1 flow, QoS 0\n64 B", r"single-flow qos=0 payload=64", "delivered_per_s"),
          ("1 flow, QoS 0\n1 KiB", r"single-flow qos=0 payload=1024", "delivered_per_s"),
          ("1 flow, QoS 1\n64 B", r"single-flow qos=1 payload=64", "delivered_per_s")]
LATENCY = [("8 pairs × 100/s\nQoS 0", r"latency qos=0 payload=64 pairs=8 rate=100", "lat_p50_ms"),
           ("8 pairs × 100/s\nQoS 1", r"latency qos=1 payload=64 pairs=8 rate=100", "lat_p50_ms"),
           ("16 pairs × 1000/s\nQoS 0", r"sweep qos=0 payload=64 rate=1000 pairs=16", "lat_p50_ms"),
           ("16 pairs × 1000/s\nQoS 1", r"sweep qos=1 payload=64 rate=1000 pairs=16", "lat_p50_ms"),
           ("1 flow flood\nQoS 0, 64 B", r"single-flow qos=0 payload=64", "lat_p50_ms")]
CPU = [("16 pairs\nQoS 0, 64 B", r"throughput qos=0 payload=64 pairs=16"),
       ("16 pairs\nQoS 1, 64 B", r"throughput qos=1 payload=64 pairs=16"),
       ("16 × 1000/s\nQoS 0", r"sweep qos=0 payload=64 rate=1000 pairs=16"),
       ("fan-out 1→100\nQoS 0", r"fanout qos=0 subs=100 rate=0")]


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    outdir = sys.argv[1]
    data = defaultdict(OrderedDict)  # vps -> broker -> (groups, idle)
    order = []
    for arg in sys.argv[2:]:
        label, _, path = arg.partition("=")
        vps, _, broker = label.partition("/")
        data[vps][broker] = parse(path)
        if broker not in order:
            order.append(broker)
    colors = {b: SERIES[i] for i, b in enumerate(order)}
    vpses = list(data)
    footer = ("urMQTT X11 suite (scripts/x11-bench.sh), 2026-11-07 to 11-09. Each VPS measured from the other VPS as the load "
              "generator; same generator for every broker on a machine; 3 repetitions, median and min-max.")

    # 1. Handshakes: lines over generator threads.
    f = Figure(vpses, "New mTLS connections per second",
               "Full TLS 1.3 handshake with a client certificate and an MQTT CONNECT, no resumption; "
               "x = concurrent generator threads. Band = min-max of 3 runs.")
    hl = []
    for ax, vps in zip(f.axes, vpses):
        hl.append(lines(ax, data[vps], THREADS, "conn_per_s", colors))
        ax.set_xticks([t[0] for t in THREADS])
        ax.set_xlabel("generator threads")
    f.fit_y()
    f.axes[0].set_ylabel("connections / s")
    f.legend(hl, order)
    f.save(outdir, "x11-handshakes", footer)

    # 2. Delivered vs offered, QoS 0 and QoS 1 (sweep): lines, with the "everything delivered" diagonal.
    for qos, spec in ((1, SWEEP1),):
        f = Figure(vpses, f"Delivered at a steady offered rate, QoS {qos}",
                   "16 publisher/subscriber pairs, 64 B, each publisher at 100, 300 and 1000 msg/s; the dashed line is "
                   "'everything offered is delivered'. Band = min-max of 3 runs.")
        hl = []
        for ax, vps in zip(f.axes, vpses):
            ax.plot([0, 16000], [0, 16000], color=INK3, lw=1, ls="--", zorder=2)
            hl.append(lines(ax, data[vps], spec, "delivered_per_s", colors))
            ax.set_xticks([s[0] for s in spec])
            ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: fmt(v)))
            ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: fmt(v)))
            ax.set_xlabel("offered messages / s (16 publishers)")
        f.fit_y()
        f.axes[0].set_ylabel("delivered messages / s")
        f.legend(hl, order)
        f.save(outdir, f"x11-sweep-qos{qos}", footer)

    # 3. Latency p50 vs offered rate: lines (log y), QoS 0.
    f = Figure(vpses, "End-to-end latency as the offered rate grows (p50)",
               "16 pairs, 64 B, QoS 0; publish-to-deliver latency measured by the generator. Band = min-max of 3 runs; "
               "log scale.")
    hl = []
    for ax, vps in zip(f.axes, vpses):
        hl.append(lines(ax, data[vps], SWEEP0, "lat_p50_ms", colors))
        ax.set_yscale("log")
        ax.yaxis.set_minor_formatter(mticker.NullFormatter())
        ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:g}"))
        ax.set_xticks([s[0] for s in SWEEP0])
        ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: fmt(v)))
        ax.set_xlabel("offered messages / s (16 publishers)")
    f.fit_y(log=True)
    f.axes[0].set_ylabel("p50 latency, ms")
    f.legend(hl, order)
    f.save(outdir, "x11-latency-sweep", footer)

    # 4. Flood throughput: bars.
    f = Figure(vpses, "Messages delivered per second under flood",
               "Publishers send as fast as the broker accepts; the subscriber side is what arrives. "
               "Whisker = min-max of 3 runs.", height=4.8)
    hl = [bars(ax, data[vps], FLOOD, colors, scale=1e-3) for ax, vps in zip(f.axes, vpses)]
    f.fit_y()
    f.axes[0].set_ylabel("thousand messages / s")
    f.legend(hl, order)
    f.save(outdir, "x11-flood", footer)

    # 5. Single flow: bars.
    f = Figure(vpses, "One TCP flow: one publisher, one subscriber",
               "The hardest case for urMQTT: a single connection each way, no parallelism to hide latency. "
               "Whisker = min-max of 3 runs.")
    hl = [bars(ax, data[vps], SINGLE, colors, scale=1e-3) for ax, vps in zip(f.axes, vpses)]
    f.fit_y()
    f.axes[0].set_ylabel("thousand messages / s delivered")
    f.legend(hl, order)
    f.save(outdir, "x11-single-flow", footer)

    # 6. Latency bars with p99 whisker.
    f = Figure(vpses, "Latency at steady rates and under a single-flow flood",
               "Bar = p50, whisker up to p99 (median over 3 runs); log scale.")
    hl = []
    for ax, vps in zip(f.axes, vpses):
        hl.append(bars(ax, data[vps], LATENCY, colors, whisker="p99"))
        ax.set_yscale("log")
        ax.yaxis.set_minor_formatter(mticker.NullFormatter())
        ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:g}"))
    f.fit_y(log=True)
    f.axes[0].set_ylabel("ms")
    f.legend(hl, order)
    f.save(outdir, "x11-latency", footer)

    # 7. Broker CPU: cores busy while delivering.
    f = Figure(vpses, "Broker CPU while delivering",
               "Cores busy in the first 14 s of each run: urMQTT from $SYS per-core busy counters, Mosquitto from /proc "
               "utime+stime (one process, at most one core). Whisker = min-max of 3 runs.")
    specs = [(label, pat, "busy_cores") for label, pat in CPU]
    hl = [bars(ax, data[vps], specs, colors) for ax, vps in zip(f.axes, vpses)]
    f.fit_y()
    f.axes[0].set_ylabel("cores busy")
    f.legend(hl, order)
    f.save(outdir, "x11-cpu", footer)

    # 8. Idle memory: lines.
    f = Figure(vpses, "Memory held with idle mTLS connections",
               "Everything the broker holds for them: urMQTT heap in use ($SYS/broker/memory/used, there is no other memory); Mosquitto process "
               "RSS (its own $SYS heap counter, 17 MB at 20 000, leaves OpenSSL's per-connection state out). Nothing published.")
    hl = []
    for ax, vps in zip(f.axes, vpses):
        handles = []
        for label, (_, idle) in data[vps].items():
            pts = [(c, idle_memory(idle, c)) for c in (0, 5000, 10000, 20000)]
            pts = [(c, m / 1e6) for c, m in pts if m is not None]
            if not pts:
                continue
            (h,) = ax.plot([p[0] for p in pts], [p[1] for p in pts], "-o", color=colors[label], lw=2, ms=5,
                           label=label)
            handles.append(h)
            ax.annotate(f"{pts[-1][1]:.0f} MB", pts[-1], xytext=(5, 0), textcoords="offset points", va="center",
                        fontsize=7.5, color=INK)
        ax.set_xlabel("idle connections")
        ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: fmt(v) if v else "0"))
        hl.append(handles)
    f.fit_y()
    f.axes[0].set_ylabel("MB")
    f.legend(hl, order)
    f.save(outdir, "x11-idle-memory", footer)


if __name__ == "__main__":
    main()
