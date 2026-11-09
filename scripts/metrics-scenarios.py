#!/usr/bin/env python3
"""The Prometheus endpoint (ADR-290) against a booted dev VM.

    scripts/metrics-scenarios.py MODE METRICS_PORT TLS_PORT CERTDIR

MODE says which image the VM runs (scripts/smoke.sh, group `metrics`, builds
them from the dev configuration plus a [metrics] section):

  allow  allow_from = ["10.0.2.0/24"] (the address QEMU's user-mode network
         gives the host), max_connections_per_ip = 2, max_connections = 4 on
         each core, request_timeout_s = 3
  deny   allow_from = ["192.0.2.0/24"]: the host is outside it; the endpoint
         must not answer at all

Standard library only. Prints one "client: <scenario> ok|FAILED" line per
scenario and exits non-zero if any failed.
"""
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import time

MODE, PORT, TLS, DIR = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
results = []


def report(name, ok, detail=""):
    results.append(ok)
    print(f"client: {name} {'ok' if ok else 'FAILED'} {detail}".rstrip(), flush=True)


def run(name, fn):
    try:
        ok, detail = fn()
    except Exception as e:  # noqa: BLE001 - a scenario that raises has failed
        ok, detail = False, f"{type(e).__name__}: {e}"
    report(name, ok, detail)


def exchange(raw, timeout=10, connect_timeout=10):
    """Sends `raw`, reads until the server closes; returns (head, body, closed)."""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=connect_timeout)
    s.settimeout(timeout)
    try:
        if raw:
            s.sendall(raw)
        data = b""
        closed = False
        while True:
            try:
                chunk = s.recv(65536)
            except ConnectionResetError:
                closed = True
                break
            if not chunk:
                closed = True
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        return head.decode("latin1"), body, closed
    finally:
        s.close()


def get(path="/metrics", extra="", method="GET", version="HTTP/1.1"):
    req = f"{method} {path} {version}\r\nHost: broker\r\n{extra}\r\n".encode()
    return exchange(req)


def status(head):
    return head.split("\r\n", 1)[0]


# ---- the text ---------------------------------------------------------------


def parse(text, openmetrics=False):
    """A strict reader of the exposition formats; returns {series: value}."""
    typed, helped, samples, current, eof = {}, set(), {}, None, False
    assert text.endswith("\n"), "no final newline"
    for line in text.split("\n")[:-1]:
        assert not eof, "text after # EOF"
        assert line, "empty line"
        if line.startswith("# HELP "):
            name, _, help_ = line[7:].partition(" ")
            assert name not in helped and help_, line
            helped.add(name)
        elif line.startswith("# TYPE "):
            name, _, kind = line[7:].partition(" ")
            assert name in helped and kind in ("counter", "gauge") and name not in typed, line
            if openmetrics and kind == "counter":
                assert not name.endswith("_total"), line
            typed[name], current = kind, name
        elif line == "# EOF":
            assert openmetrics, "# EOF in the classic format"
            eof = True
        else:
            series, _, value = line.rpartition(" ")
            name = series.split("{", 1)[0]
            kind = typed[current]
            want = current + "_total" if openmetrics and kind == "counter" else current
            assert name == want, f"sample outside its family: {line}"
            float(value)
            assert not value.startswith("+") and "e" not in value.lower() and "n" not in value.lower(), line
            if kind == "counter":
                assert not value.startswith("-"), line
            assert series not in samples, f"duplicate series {series}"
            samples[series] = value
    assert eof == openmetrics, "# EOF exactly in OpenMetrics"
    return samples


def scrape(extra="", openmetrics=False):
    head, body, closed = get(extra=extra)
    assert status(head) == "HTTP/1.1 200 OK", head
    assert closed, "the server did not close"
    return head, parse(body.decode(), openmetrics)


# ---- scenarios (allow) ---------------------------------------------------------


def prometheus_text():
    head, body, closed = get()
    assert status(head) == "HTTP/1.1 200 OK" and closed, head
    s = parse(body.decode())
    h = head.lower()
    assert "content-type: text/plain; version=0.0.4; charset=utf-8" in h, head
    assert "connection: close" in h, head
    length = int(next(x.split(":")[1] for x in h.split("\r\n") if x.startswith("content-length")))
    assert length == len(body), (length, len(body))
    need = ["urmqtt_uptime_seconds", "urmqtt_cpu_cores", "urmqtt_memory_heap_bytes", "urmqtt_clients_connected",
            "urmqtt_messages_received_total", "urmqtt_handshakes_done_total", "urmqtt_metrics_listener_port",
            'urmqtt_cpu_busy_ratio{core="0"}', 'urmqtt_listener_enabled{listener="websocket"}']
    missing = [n for n in need if n not in s]
    assert not missing, missing
    assert s["urmqtt_metrics_listener_port"] == "9100", s["urmqtt_metrics_listener_port"]
    assert s["urmqtt_cpu_cores"] == "4", s["urmqtt_cpu_cores"]
    # No per-client labels: every label name is on the bounded list.
    labels = {k.split("{", 1)[1].split("=", 1)[0] for k in s if "{" in k}
    allowed = {"core", "reason", "code", "listener", "result", "direction", "side", "version", "arch", "source", "mode", "state", "auth"}
    assert labels <= allowed, labels - allowed
    return True, f"{len(s)} series"


def openmetrics_text():
    om = "Accept: application/openmetrics-text;version=1.0.0;q=0.5,text/plain;version=0.0.4;q=0.4,*/*;q=0.1\r\n"
    head, s = scrape(om, openmetrics=True)
    assert "content-type: application/openmetrics-text; version=1.0.0; charset=utf-8" in head.lower(), head
    _, plain = scrape("Accept: text/plain\r\n")
    assert set(s) == set(plain), "the two formats carry different series"
    return True, f"{len(s)} series"


def head_request():
    head, body, closed = get(method="HEAD")
    assert status(head) == "HTTP/1.1 200 OK" and body == b"" and closed, (head, body)
    assert int(next(x.split(":")[1] for x in head.lower().split("\r\n") if x.startswith("content-length"))) > 1000
    return True, ""


def refusals():
    cases = [
        ("404 other path", get("/other"), "HTTP/1.1 404"),
        ("404 query", get("/metrics?x=1"), "HTTP/1.1 404"),
        ("405 POST", get(method="POST"), "HTTP/1.1 405"),
        ("505 version", get(version="HTTP/2.0"), "HTTP/1.1 505"),
        ("400 body", get(extra="Content-Length: 5\r\n"), "HTTP/1.1 400"),
        ("400 chunked", get(extra="Transfer-Encoding: chunked\r\n"), "HTTP/1.1 400"),
        ("400 garbage", exchange(b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\r\n\r\n"), "HTTP/1.1 400"),
        ("400 bare LF", exchange(b"GET /metrics HTTP/1.1\nHost: x\n\r\n\r\n"), "HTTP/1.1 400"),
        ("431 large", get(extra="X-Pad: " + "a" * 3000 + "\r\n"), "HTTP/1.1 431"),
    ]
    bad = []
    for name, (head, body, closed), want in cases:
        if not status(head).startswith(want) or body or not closed:
            bad.append((name, status(head), len(body), closed))
        # The answer names nothing the client sent.
    return not bad, str(bad) if bad else f"{len(cases)} refusals"


def pipelined():
    one = b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"
    head, body, closed = exchange(one + one)
    assert closed and status(head) == "HTTP/1.1 200 OK"
    assert body.count(b"# EOF") == 0 and body.count(b"HTTP/1.1 200") == 0, "a second answer"
    return True, ""


def request_in_pieces():
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    for piece in (b"GET /met", b"rics HT", b"TP/1.1\r\nHo", b"st: x\r\n", b"\r\n"):
        s.sendall(piece)
        time.sleep(0.2)
    data = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        data += c
    s.close()
    return data.startswith(b"HTTP/1.1 200 OK"), ""


def slowloris():
    """Headers that never end are cut at request_timeout_s (3 s), and the
    place is free again."""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    s.sendall(b"GET /metrics HTTP/1.1\r\nHost: x\r\n")
    t0 = time.time()
    s.settimeout(1)
    cut = None
    while time.time() - t0 < 12:
        try:
            if s.recv(1) == b"":
                cut = time.time() - t0
                break
        except socket.timeout:
            # a drip of header bytes does not extend the deadline
            try:
                s.sendall(b"X: y\r\n")
            except OSError:
                cut = time.time() - t0
                break
        except ConnectionResetError:
            cut = time.time() - t0
            break
    s.close()
    ok = cut is not None and 2.5 <= cut <= 8
    head, _, _ = get()
    return ok and status(head) == "HTTP/1.1 200 OK", f"cut after {cut and round(cut, 1)} s"


def per_address_limit():
    """16 connections that never finish a request, from one address: at most
    max_connections_per_ip (2) per core are held, the others' SYNs get no
    answer (QEMU's forwarder keeps retrying them, so the host side connects
    at once and nothing here can tell; the endpoint's own counter does, in the
    scenario after the next one)."""
    held = []
    for _ in range(16):
        s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        s.sendall(b"GET /metrics HTTP/1.1\r\nHost: x\r\n")
        held.append(s)
    time.sleep(1.5)
    for s in held:
        s.close()
    time.sleep(1)
    return True, f"{len(held)} connections opened"


def counters_after_the_deadline():
    time.sleep(4)  # the idle connections of the scenarios above are cut
    _, s = scrape()
    g = lambda k: int(s.get(k, "-1"))  # noqa: E731
    checks = {
        "timeouts": g("urmqtt_metrics_timeouts_total") >= 1,
        "ok": g('urmqtt_metrics_requests_total{result="ok"}') >= 8,
        "method": g('urmqtt_metrics_requests_total{result="method"}') == 1,
        "not_found": g('urmqtt_metrics_requests_total{result="not_found"}') == 2,
        "version": g('urmqtt_metrics_requests_total{result="version"}') == 1,
        "too_large": g('urmqtt_metrics_requests_total{result="too_large"}') == 1,
        "malformed": g('urmqtt_metrics_requests_total{result="malformed"}') >= 4,
        "limit": g('urmqtt_metrics_refused_total{reason="limit"}') >= 4,
        "source": g('urmqtt_metrics_refused_total{reason="source"}') == 0,
    }
    return all(checks.values()), " ".join(f"{k}={'ok' if v else 'NO'}" for k, v in checks.items())


# ---- against $SYS ---------------------------------------------------------------


def mqtt(args):
    cert = os.path.join(DIR, "services/operator")
    return ["-h", "127.0.0.1", "-p", str(TLS), "--cafile", os.path.join(DIR, "ca.pem"), "--cert", cert + ".pem",
            "--key", cert + ".key", "--insecure", "-V", "mqttv311", *args]


def sys_value(topic):
    out = subprocess.run(["mosquitto_sub", *mqtt(["-i", "operator", "-t", topic, "-C", "1", "-W", "8"])],
                         capture_output=True, text=True, timeout=15)
    return out.stdout.strip() or None


def read_packet(sock):
    def need(n):
        data = b""
        while len(data) < n:
            c = sock.recv(n - len(data))
            if not c:
                raise EOFError("closed")
            data += c
        return data

    first = need(1)[0]
    n, shift = 0, 0
    while True:
        b = need(1)[0]
        n |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            break
    return first, need(n)


def info_query():
    """The operator asks $SYS/query/info over mutual TLS (a minimal MQTT 3.1.1
    client; one connection, so one client id) and returns the JSON reply."""
    cert = os.path.join(DIR, "services/operator")
    ctx = ssl.create_default_context(cafile=os.path.join(DIR, "ca.pem"))
    ctx.check_hostname = False
    ctx.load_cert_chain(cert + ".pem", cert + ".key")
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", TLS), timeout=10))
    s.settimeout(15)

    def mstr(x):
        return struct.pack(">H", len(x)) + x.encode()

    def packet(first, body):
        return bytes([first, len(body)]) + body  # all bodies here are under 128 bytes

    try:
        s.sendall(packet(0x10, mstr("MQTT") + bytes([4, 2]) + struct.pack(">H", 60) + mstr("operator")))
        assert read_packet(s) == (0x20, b"\x00\x00"), "CONNACK"
        s.sendall(packet(0x82, struct.pack(">H", 1) + mstr("$SYS/query/info/response") + b"\x00"))
        first, body = read_packet(s)
        assert first == 0x90, "SUBACK"
        s.sendall(packet(0x30, mstr("$SYS/query/info")))
        while True:
            first, body = read_packet(s)
            if first >> 4 == 3:
                tl = struct.unpack(">H", body[:2])[0]
                assert body[2 : 2 + tl] == b"$SYS/query/info/response"
                return json.loads(body[2 + tl :])
    finally:
        s.close()


def agrees_with_sys():
    """The endpoint and the info query report the same machine: the same
    version, architecture, core count, heap, MTU; counters are at least what
    the query saw."""
    q = info_query()
    _, s = scrape()
    checks = {
        "version": s.get(f'urmqtt_version_info{{version="{q["version"]}"}}') == "1",
        "arch": s.get(f'urmqtt_arch_info{{arch="{q["arch"]}"}}') == "1",
        "cores": s["urmqtt_cpu_cores"] == str(q["cpu"]["cores"]),
        "heap": s["urmqtt_memory_heap_bytes"] == str(q["memory"]["total"]),
        "mtu": s["urmqtt_network_mtu_bytes"] == str(q["net"]["mtu"]),
        "disk": s["urmqtt_disk_bytes"] == str(q["disk"]["total"]),
        "received": int(s["urmqtt_messages_received_total"]) >= q["messages"]["received"],
        "started": int(s["urmqtt_handshakes_started_total"]) >= q["handshakes"]["started"],
        "cores-busy": all(f'urmqtt_cpu_busy_ratio{{core="{i}"}}' in s for i in range(q["cpu"]["cores"])),
        "accepted": all(f'urmqtt_core_connections_accepted_total{{core="{i}"}}' in s for i in range(len(q["accepted"]))),
    }
    # And the retained topic of the tree.
    topic_version = sys_value("$SYS/broker/version")
    checks["topic-version"] = topic_version == q["version"]
    return all(checks.values()), " ".join(k for k, v in checks.items() if not v) or "all agree"


def counters_follow_traffic():
    """A counter grows by what was published (QoS 0, within a second's report)."""
    _, before = scrape()
    n = 25
    cert = os.path.join(DIR, "devices/device-001")
    for _ in range(n):
        subprocess.run(["mosquitto_pub", "-h", "127.0.0.1", "-p", str(TLS), "--cafile", os.path.join(DIR, "ca.pem"),
                        "--cert", cert + ".pem", "--key", cert + ".key", "--insecure", "-V", "mqttv311", "-i", "device-001",
                        "-t", "devices/device-001/t", "-m", "x", "-q", "0"], timeout=15, check=True)
    time.sleep(2.5)  # the shards publish their counters every second
    _, after = scrape()
    d = int(after["urmqtt_messages_received_total"]) - int(before["urmqtt_messages_received_total"])
    done = int(after["urmqtt_handshakes_done_total"]) - int(before["urmqtt_handshakes_done_total"])
    return d >= n and done >= n, f"messages +{d}, handshakes +{done} for {n} publishes"


# ---- deny -------------------------------------------------------------------------


def deny_no_http_bytes():
    """The host's address (10.0.2.2) is not in allow_from: the SYN gets no
    answer, so QEMU's forwarder never reaches the guest and not one byte of
    HTTP, a RST or an error page comes back that would say a listener is
    there."""
    s = socket.socket()
    s.settimeout(4)
    try:
        s.connect(("127.0.0.1", PORT))
        s.sendall(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        data = s.recv(100)
    except OSError:
        data = b""
    finally:
        s.close()
    return data == b"", repr(data[:20])


if MODE == "allow":
    run("metrics-prometheus-text-0.0.4", prometheus_text)
    run("metrics-openmetrics-negotiated", openmetrics_text)
    run("metrics-head-has-no-body", head_request)
    run("metrics-refusals-404-405-505-400-431", refusals)
    run("metrics-pipelined-request-answered-once", pipelined)
    run("metrics-request-in-pieces", request_in_pieces)
    run("metrics-slowloris-cut-at-the-deadline", slowloris)
    run("metrics-per-address-limit-opened", per_address_limit)
    run("metrics-listener-counters", counters_after_the_deadline)
    run("metrics-agree-with-the-info-query", agrees_with_sys)
    run("metrics-counters-follow-traffic", counters_follow_traffic)
elif MODE == "deny":
    run("metrics-outside-allow-from-gets-no-bytes", deny_no_http_bytes)
else:
    sys.exit(f"unknown mode {MODE}")
sys.exit(0 if all(results) else 1)
