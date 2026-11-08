import socket, ssl, sys, time
port=int(sys.argv[1]); d=sys.argv[2]
def tcp(n):
    r=[]
    for i in range(n):
        t=time.perf_counter(); s=socket.create_connection(("127.0.0.1",port)); s.close(); r.append((time.perf_counter()-t)*1000)
    r.sort(); return r
def tls(n):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.load_verify_locations(f"{d}/ca.pem"); ctx.check_hostname=False
    ctx.load_cert_chain(f"{d}/devices/device-001.pem", f"{d}/devices/device-001.key")
    r=[]
    for i in range(n):
        t=time.perf_counter(); s=socket.create_connection(("127.0.0.1",port)); w=ctx.wrap_socket(s); r.append((time.perf_counter()-t)*1000); w.close()
        time.sleep(0.02)
    r.sort(); return r
for name,f,n in (("tls handshake",tls,40),):
    r=f(n); print(f"{name}: p50 {r[len(r)//2]:.1f} ms p90 {r[int(len(r)*.9)]:.1f} ms max {r[-1]:.1f} n={n}")
