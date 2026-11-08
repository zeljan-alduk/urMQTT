import socket, sys, time, statistics
port=int(sys.argv[1]); n=int(sys.argv[2]); gap=float(sys.argv[3])
s=socket.create_connection(("127.0.0.1",port)); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,1)
r=[]
for i in range(n):
    t=time.perf_counter(); s.sendall(b"x"); s.recv(1); r.append((time.perf_counter()-t)*1000); time.sleep(gap)
r.sort(); print(f"echo rtt ms: p50 {r[len(r)//2]:.2f} p90 {r[int(len(r)*.9)]:.2f} max {r[-1]:.2f} n={n} gap={gap}")
