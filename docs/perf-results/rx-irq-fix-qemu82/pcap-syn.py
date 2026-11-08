import struct, sys
data=open(sys.argv[1],'rb').read(); off=24; syn={}; rows=[]; prev=None
while off+16<=len(data):
    ts,tu,incl,orig=struct.unpack_from('<IIII',data,off); f=data[off+16:off+16+incl]; off+=16+incl
    t=ts+tu/1e6
    if f[12:14]!=b'\x08\x00' or f[23]!=6: continue
    ihl=(f[14]&15)*4; tcp=f[14+ihl:]; sp,dp=struct.unpack('>HH',tcp[:4]); fl=tcp[13]
    if dp==8883 and fl&0x02 and not fl&0x10: syn.setdefault(sp,[]).append(t)
    if sp==8883 and fl&0x12==0x12 and dp in syn: rows.append((syn[dp][0], t-syn[dp][0], len(syn[dp])))
rows.sort(); gaps=[b[0]-a[0] for a,b in zip(rows,rows[1:])]
import statistics as s
print(f"conns {len(rows)} synack delay ms p50 {s.median([r[1]*1000 for r in rows]):.2f} max {max(r[1]*1000 for r in rows):.2f}; SYN retransmits {sum(r[2]-1 for r in rows)}; gap between connects ms p50 {s.median(gaps)*1000:.1f}")
