### results/contabo-urmqtt-v042-from-netcup.txt

| handshake | conn/s | errors | p50 ms | p99 ms | TLS p50 ms | gen cpu | broker busy % (cores, first 14 s) |
|---|---|---|---|---|---|---|---|
| threads=32 | 610 (570-672) | 0 (0-0) | 42 (38-42) | 140 (99-331) | 22 (20-22) | 0.76 (0.71-0.86) | c0=32 c1=28 c2=28 c3=64 |
| threads=64 | 1094 (942-1247) | 0 (0-0) | 52 (45-56) | 127 (101-176) | 28 (24-30) | 1.18 (1.05-1.31) | c0=33 c1=36 c2=37 c3=76 |
| threads=128 | 1830 (1368-1834) | 0 (0-0) | 64 (59-66) | 260 (165-379) | 36 (33-37) | 1.73 (1.42-1.74) | c0=37 c1=57 c2=57 c3=80 |

| throughput | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=16 | 190640 (164658-203148) | 125142 (90736-155708) | 0 (0-0) | 708.0 (650.3-1181.4) | 3579.3 (1620.2-4558.6) | 0 (0-0) | 0.84 (0.79-0.94) | c0=41 c1=91 c2=96 c3=41 | steal=7% idle=49% user+sys=22% |
| qos=0 payload=1024 pairs=16 | 20630 (20190-21237) | 20265 (19770-20912) | 0 (0-0) | 368.8 (364.6-1064.6) | 1805.9 (999.0-2304.7) | 0 (0-0) | 0.76 (0.76-0.82) | c0=42 c1=36 c2=36 c3=41 | steal=6% idle=47% user+sys=21% |
| qos=1 payload=64 pairs=16 | 45327 (33386-46775) | 22358 (18372-23658) | 45327 (33386-46775) | 45.1 (43.0-48.6) | 144.4 (122.2-227.4) | 0 (0-0) | 0.74 (0.60-0.75) | c0=26 c1=19 c2=20 c3=33 | steal=7% idle=53% user+sys=20% |
| qos=1 payload=1024 pairs=16 | 21696 (20716-21886) | 12559 (11867-12735) | 21696 (20716-21886) | 87.6 (85.5-88.7) | 322.2 (321.1-415.7) | 0 (0-0) | 0.77 (0.71-0.77) | c0=16 c1=6 c2=6 c3=39 | steal=6% idle=52% user+sys=18% |
| qos=1 payload=64 pairs=64 | 97130 (74676-101339) | 50064 (38179-52475) | 97132 (74673-101344) | 80.0 (77.5-108.2) | 289.9 (271.0-397.1) | 0 (0-0) | 1.48 (1.35-1.53) | c0=4 c1=2 c2=2 c3=19 | steal=2% idle=27% user+sys=46% |

| sweep | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 rate=100 pairs=16 | 1600 (1600-1600) | 1600 (1600-1600) | 0 (0-0) | 8.0 (7.9-8.3) | 30.4 (25.9-34.7) | 0 (0-0) | 0.30 (0.29-0.31) | c0=28 c1=12 c2=13 c3=29 | steal=9% idle=72% user+sys=8% |
| qos=0 payload=64 rate=300 pairs=16 | 4800 (4800-4800) | 4800 (4798-4801) | 0 (0-0) | 8.3 (7.8-8.3) | 29.7 (27.5-35.9) | 0 (0-0) | 0.47 (0.44-0.49) | c0=21 c1=10 c2=12 c3=31 | steal=8% idle=68% user+sys=9% |
| qos=0 payload=64 rate=1000 pairs=16 | 16000 (16000-16000) | 15999 (15994-16002) | 0 (0-0) | 11.1 (10.5-15.4) | 137.8 (104.2-166.8) | 0 (0-0) | 0.75 (0.74-0.77) | c0=11 c1=2 c2=3 c3=22 | steal=4% idle=43% user+sys=25% |
| qos=1 payload=64 rate=100 pairs=16 | 1600 (1600-1600) | 1601 (1592-1604) | 1600 (1592-1604) | 8.4 (7.9-11.2) | 29.9 (26.6-57.7) | 0 (0-0) | 0.34 (0.31-0.36) | c0=34 c1=17 c2=17 c3=23 | steal=8% idle=72% user+sys=7% |
| qos=1 payload=64 rate=300 pairs=16 | 4800 (4800-4800) | 4800 (4798-4800) | 4800 (4799-4800) | 8.6 (7.8-14.4) | 39.5 (31.9-65.6) | 0 (0-0) | 0.55 (0.55-0.56) | c0=44 c1=36 c2=36 c3=27 | steal=7% idle=58% user+sys=14% |
| qos=1 payload=64 rate=1000 pairs=16 | 16000 (15745-16000) | 15227 (12492-15675) | 15992 (15736-16005) | 11.1 (9.2-58.2) | 158.6 (103.2-257.8) | 0 (0-0) | 0.82 (0.68-0.89) | c0=37 c1=37 c2=37 c3=54 | steal=6% idle=63% user+sys=14% |
| qos=0 payload=1024 rate=100 pairs=16 | 1600 (1600-1600) | 1600 (1600-1601) | 0 (0-0) | 9.8 (9.2-12.0) | 45.1 (36.8-76.3) | 0 (0-0) | 0.31 (0.30-0.33) | c0=27 c1=13 c2=13 c3=29 | steal=8% idle=68% user+sys=10% |
| qos=0 payload=1024 rate=300 pairs=16 | 4800 (4800-4801) | 4800 (4736-4801) | 0 (0-0) | 11.1 (8.8-11.3) | 61.5 (32.6-222.0) | 0 (0-0) | 0.49 (0.46-0.50) | c0=18 c1=9 c2=10 c3=29 | steal=7% idle=68% user+sys=9% |

| single-flow | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=1024 | 7765 (6620-9572) | 7152 (5010-8264) | 0 (0-0) | 286.8 (133.6-1129.6) | 577.7 (492.3-1687.6) | 0 (0-0) | 0.17 (0.13-0.18) | c0=31 c1=34 c2=28 c3=27 | steal=5% idle=84% user+sys=3% |
| qos=0 payload=64 | 59371 (43607-74942) | 53785 (33849-71696) | 0 (0-0) | 427.4 (391.8-966.1) | 797.2 (487.8-1598.7) | 0 (0-0) | 0.22 (0.19-0.26) | c0=32 c1=54 c2=39 c3=18 | steal=5% idle=78% user+sys=6% |
| qos=1 payload=64 | 3774 (1844-3885) | 1794 (1659-1811) | 3774 (1844-3885) | 37.3 (37.0-39.3) | 87.8 (84.4-244.8) | 0 (0-0) | 0.09 (0.07-0.10) | c0=26 c1=7 c2=12 c3=23 | steal=5% idle=88% user+sys=3% |

| latency | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=8 rate=100 | 800 (800-800) | 800 (800-800) | 0 (0-0) | 10.2 (8.5-11.9) | 37.2 (30.0-50.7) | 0 (0-0) | 0.19 (0.19-0.20) | c0=28 c1=16 c2=16 c3=25 | steal=7% idle=80% user+sys=4% |
| qos=1 payload=64 pairs=8 rate=100 | 800 (800-800) | 800 (800-800) | 800 (800-800) | 9.4 (9.0-10.5) | 51.2 (31.6-58.8) | 0 (0-0) | 0.21 (0.21-0.22) | c0=29 c1=15 c2=16 c3=37 | steal=6% idle=79% user+sys=6% |

| fanout | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 subs=100 rate=50 | 50 (50-50) | 5000 (5000-5005) | 0 (0-0) | 10.5 (10.4-11.9) | 33.2 (30.2-43.8) | 0 (0-0) | 0.19 (0.19-0.20) | c0=24 c1=7 c2=6 c3=30 | steal=5% idle=83% user+sys=5% |
| qos=0 subs=1000 rate=10 | 10 (10-10) | 10000 (10000-10000) | 0 (0-0) | 27.9 (24.9-28.7) | 117.4 (86.0-198.2) | 0 (0-0) | 0.41 (0.41-0.41) | c0=17 c1=11 c2=8 c3=27 | steal=5% idle=77% user+sys=7% |
| qos=1 subs=100 rate=50 | 50 (50-50) | 5001 (4984-5020) | 50 (50-50) | 10.4 (9.8-15.8) | 35.0 (32.1-93.7) | 0 (0-0) | 0.26 (0.24-0.27) | c0=14 c1=4 c2=5 c3=59 | steal=6% idle=79% user+sys=6% |
| qos=0 subs=100 rate=0 | 38691 (26823-46118) | 275582 (268490-280554) | 0 (0-0) | 1781.8 (1728.5-2853.1) | 5732.1 (4836.1-5902.1) | 0 (0-0) | 0.34 (0.31-0.36) | c0=47 c1=100 c2=100 c3=42 | steal=7% idle=69% user+sys=8% |

| idle connections | broker clients | broker memory (bytes) | detail |
|---|---|---|---|
| baseline | 1 | 7432192 |   |
| 5000 | 5000 | 10019840 | IDLE opened_in=6s errors=0 first: ; IDLE generator_rss_kb=56792 generator_threads=1; loadgen: hold: 5000 of 5000 connections established in 4.5 s  |
| after close | 1 | 7494144 |   |
| 10000 | 10000 | 12640256 | IDLE opened_in=11s errors=0 first: ; IDLE generator_rss_kb=105944 generator_threads=1; loadgen: hold: 10000 of 10000 connections established in 8.9 s  |
| after close | 1 | 7418368 |   |
| 20000 | 20000 | 17915904 | IDLE opened_in=40s errors=0 first: ; IDLE generator_rss_kb=204680 generator_threads=1; loadgen: hold: 20000 of 20000 connections established in 38.6 s  |
| after close | 1 | 7492096 |   |


### results/contabo-urmqtt-sack-from-netcup.txt

| handshake | conn/s | errors | p50 ms | p99 ms | TLS p50 ms | gen cpu | broker busy % (cores, first 14 s) |
|---|---|---|---|---|---|---|---|
| threads=32 | 714 (688-731) | 0 (0-0) | 35 (34-38) | 100 (90-233) | 19 (18-20) | 0.87 (0.83-0.89) | c0=31 c1=24 c2=23 c3=78 |
| threads=64 | 1449 (1221-1467) | 0 (0-0) | 38 (38-43) | 89 (85-148) | 21 (21-24) | 1.36 (1.25-1.38) | c0=26 c1=18 c2=19 c3=80 |
| threads=128 | 1956 (1912-1985) | 0 (0-0) | 61 (60-62) | 131 (131-132) | 35 (34-35) | 1.78 (1.76-1.82) | c0=45 c1=65 c2=63 c3=87 |

| throughput | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=16 | 235027 (231360-240311) | 201120 (181864-212313) | 0 (0-0) | 399.4 (396.7-496.3) | 1031.1 (909.7-1237.4) | 0 (0-0) | 1.01 (0.98-1.09) | c0=19 c1=38 c2=35 c3=31 | steal=2% idle=39% user+sys=26% |
| qos=0 payload=1024 pairs=16 | 22865 (22476-22995) | 22170 (21857-22249) | 0 (0-0) | 401.7 (302.2-485.7) | 1283.9 (1054.7-1452.1) | 0 (0-0) | 0.80 (0.79-0.81) | c0=54 c1=50 c2=49 c3=44 | steal=6% idle=47% user+sys=18% |
| qos=1 payload=64 pairs=16 | 40090 (31083-45942) | 22293 (17947-24612) | 40092 (31083-45942) | 43.2 (40.7-55.7) | 141.1 (121.6-211.3) | 0 (0-0) | 0.64 (0.55-0.69) | c0=46 c1=41 c2=41 c3=40 | steal=7% idle=55% user+sys=18% |
| qos=1 payload=1024 pairs=16 | 22084 (21085-22138) | 11436 (10881-12295) | 22084 (21085-22138) | 94.7 (91.9-102.9) | 293.3 (293.0-327.7) | 0 (0-0) | 0.73 (0.72-0.74) | c0=49 c1=35 c2=33 c3=43 | steal=5% idle=52% user+sys=18% |
| qos=1 payload=64 pairs=64 | 135296 (126853-149364) | 68956 (61500-78143) | 135300 (126853-149363) | 58.8 (53.1-59.6) | 257.5 (192.2-290.9) | 0 (0-0) | 1.67 (1.62-1.74) | c0=70 c1=77 c2=79 c3=28 | steal=4% idle=15% user+sys=46% |

| sweep | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 rate=100 pairs=16 | 1600 (1600-1600) | 1600 (1600-1600) | 0 (0-0) | 7.9 (6.9-9.2) | 29.0 (18.2-34.0) | 0 (0-0) | 0.33 (0.32-0.34) | c0=32 c1=19 c2=18 c3=29 | steal=9% idle=74% user+sys=7% |
| qos=0 payload=64 rate=300 pairs=16 | 4800 (4800-4800) | 4800 (4800-4801) | 0 (0-0) | 7.8 (7.5-7.9) | 22.7 (22.1-23.9) | 0 (0-0) | 0.52 (0.49-0.56) | c0=38 c1=22 c2=22 c3=25 | steal=7% idle=57% user+sys=15% |
| qos=0 payload=64 rate=1000 pairs=16 | 16000 (15437-16000) | 15995 (15252-15999) | 0 (0-0) | 7.3 (7.2-49.4) | 27.2 (23.4-2348.5) | 0 (0-0) | 0.94 (0.60-0.95) | c0=32 c1=17 c2=16 c3=22 | steal=6% idle=55% user+sys=18% |
| qos=1 payload=64 rate=100 pairs=16 | 1600 (1600-1600) | 1601 (1600-1601) | 1601 (1600-1601) | 7.5 (7.5-8.1) | 24.7 (22.9-30.5) | 0 (0-0) | 0.37 (0.36-0.37) | c0=12 c1=5 c2=5 c3=14 | steal=9% idle=70% user+sys=9% |
| qos=1 payload=64 rate=300 pairs=16 | 4800 (4800-4800) | 4801 (4800-4801) | 4800 (4800-4801) | 7.5 (7.4-8.1) | 28.6 (27.4-48.4) | 0 (0-0) | 0.62 (0.61-0.63) | c0=13 c1=6 c2=6 c3=15 | steal=6% idle=55% user+sys=17% |
| qos=1 payload=64 rate=1000 pairs=16 | 16000 (15999-16000) | 15683 (15140-15765) | 16000 (15984-16002) | 8.6 (7.8-15.8) | 124.0 (95.9-134.6) | 0 (0-0) | 0.93 (0.79-0.97) | c0=39 c1=34 c2=31 c3=28 | steal=8% idle=57% user+sys=13% |
| qos=0 payload=1024 rate=100 pairs=16 | 1600 (1600-1600) | 1599 (1599-1601) | 0 (0-0) | 7.5 (6.9-7.7) | 23.6 (22.8-25.1) | 0 (0-0) | 0.34 (0.33-0.36) | c0=33 c1=20 c2=18 c3=27 | steal=8% idle=66% user+sys=12% |
| qos=0 payload=1024 rate=300 pairs=16 | 4800 (4800-4800) | 4800 (4800-4803) | 0 (0-0) | 7.2 (7.1-8.1) | 24.1 (23.8-24.3) | 0 (0-0) | 0.56 (0.52-0.58) | c0=39 c1=25 c2=24 c3=24 | steal=9% idle=61% user+sys=11% |

| single-flow | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=1024 | 10594 (6504-14667) | 9956 (6240-13552) | 0 (0-0) | 277.1 (139.6-446.9) | 600.5 (212.0-932.2) | 0 (0-0) | 0.22 (0.17-0.26) | c0=42 c1=28 c2=27 c3=16 | steal=7% idle=73% user+sys=4% |
| qos=0 payload=64 | 93628 (87174-106607) | 86664 (71033-96592) | 0 (0-0) | 221.8 (130.1-548.9) | 475.3 (273.2-760.1) | 0 (0-0) | 0.34 (0.32-0.35) | c0=42 c1=71 c2=32 c3=16 | steal=6% idle=72% user+sys=7% |
| qos=1 payload=64 | 4216 (4044-4280) | 2117 (1965-2173) | 4216 (4044-4280) | 33.2 (32.7-34.0) | 67.5 (55.9-248.7) | 0 (0-0) | 0.10 (0.10-0.11) | c0=31 c1=14 c2=11 c3=18 | steal=5% idle=87% user+sys=3% |

| latency | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=8 rate=100 | 800 (800-800) | 800 (800-800) | 0 (0-0) | 7.0 (6.8-7.3) | 19.6 (16.9-19.8) | 0 (0-0) | 0.18 (0.17-0.18) | c0=29 c1=12 c2=13 c3=30 | steal=7% idle=82% user+sys=4% |
| qos=1 payload=64 pairs=8 rate=100 | 800 (800-800) | 800 (800-800) | 800 (799-800) | 6.8 (6.7-8.5) | 19.7 (16.7-38.0) | 0 (0-0) | 0.19 (0.19-0.19) | c0=31 c1=10 c2=10 c3=27 | steal=7% idle=76% user+sys=8% |

| fanout | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 subs=100 rate=50 | 50 (50-50) | 5000 (5000-5001) | 0 (0-0) | 9.2 (8.9-9.3) | 24.2 (23.3-24.3) | 0 (0-0) | 0.18 (0.18-0.19) | c0=22 c1=6 c2=6 c3=30 | steal=5% idle=83% user+sys=5% |
| qos=0 subs=1000 rate=10 | 10 (10-10) | 10000 (9999-10000) | 0 (0-0) | 21.4 (20.2-22.5) | 46.5 (37.4-55.6) | 0 (0-0) | 0.38 (0.37-0.41) | c0=34 c1=12 c2=11 c3=19 | steal=6% idle=74% user+sys=9% |
| qos=1 subs=100 rate=50 | 50 (50-50) | 5000 (5000-5000) | 50 (50-50) | 9.7 (8.9-9.9) | 29.3 (20.1-36.1) | 0 (0-0) | 0.25 (0.25-0.25) | c0=32 c1=15 c2=14 c3=28 | steal=6% idle=79% user+sys=6% |
| qos=0 subs=100 rate=0 | 92370 (89432-123487) | 286933 (279823-287777) | 0 (0-0) | 444.9 (407.0-597.5) | 4995.9 (4865.5-6125.4) | 0 (0-0) | 0.44 (0.44-0.50) | c0=40 c1=57 c2=70 c3=31 | steal=7% idle=61% user+sys=9% |

| idle connections | broker clients | broker memory (bytes) | detail |
|---|---|---|---|
| baseline | 1 | 7301120 |   |
| 5000 | 5000 | 9841152 | IDLE opened_in=5s errors=0 first: ; IDLE generator_rss_kb=56648 generator_threads=1; loadgen: hold: 5000 of 5000 connections established in 3.7 s  |
| after close | 1 | 7285760 |   |
| 10000 | 10000 | 12391936 | IDLE opened_in=8s errors=0 first: ; IDLE generator_rss_kb=105424 generator_threads=1; loadgen: hold: 10000 of 10000 connections established in 5.8 s  |
| after close | 1 | 7322624 |   |
| 20000 | 20001 | 17590272 | IDLE opened_in=38s errors=0 first: ; IDLE generator_rss_kb=204680 generator_threads=1; loadgen: hold: 20000 of 20000 connections established in 36.3 s  |
| after close | 20000 | 19793920 |   |


### results/contabo-mosquitto-from-netcup.txt

| handshake | conn/s | errors | p50 ms | p99 ms | TLS p50 ms | gen cpu | broker busy % (cores, first 14 s) |
|---|---|---|---|---|---|---|---|
| threads=32 | 337 (336-348) | 0 (0-0) | 84 (83-86) | 171 (146-218) | 68 (68-70) | 0.49 (0.48-0.50) | mosquitto 72% of one core |
| threads=64 | 610 (583-610) | 0 (0-0) | 97 (96-102) | 180 (170-184) | 76 (76-79) | 0.81 (0.74-0.82) | mosquitto 96% of one core |
| threads=128 | 639 (599-697) | 0 (0-0) | 184 (176-204) | 302 (259-490) | 130 (124-147) | 0.82 (0.75-0.83) | mosquitto 99% of one core |

| throughput | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=16 | 60957 (54512-61826) | 60420 (53615-61345) | 0 (0-0) | 1550.4 (1535.1-1817.5) | 3051.0 (2891.1-4124.8) | 0 (0-0) | 0.78 (0.77-0.78) | mosquitto 100% of one core | steal=6% idle=53% user+sys=21% |
| qos=0 payload=1024 pairs=16 | 23086 (23056-23171) | 22146 (22066-22285) | 0 (0-0) | 817.8 (791.9-918.5) | 1723.2 (1583.8-1808.0) | 0 (0-0) | 0.92 (0.89-0.96) | mosquitto 78% of one core | steal=5% idle=41% user+sys=20% |
| qos=1 payload=64 pairs=16 | 36534 (34579-36754) | 18870 (18713-19004) | 36534 (34579-36753) | 806.9 (801.1-812.2) | 1890.1 (1883.2-1901.3) | 0 (0-0) | 0.82 (0.82-0.89) | mosquitto 94% of one core | steal=5% idle=49% user+sys=22% |
| qos=1 payload=1024 pairs=16 | 20420 (19763-20788) | 18660 (18052-18687) | 20420 (19763-20788) | 403.6 (84.9-537.9) | 1388.4 (1384.9-1425.9) | 0 (0-0) | 1.11 (1.05-1.14) | mosquitto 97% of one core | steal=4% idle=35% user+sys=28% |
| qos=1 payload=64 pairs=64 | 30037 (19566-32467) | 29990 (19586-32452) | 30037 (19566-32468) | 68.0 (62.6-106.2) | 190.9 (174.2-236.3) | 0 (0-0) | 1.63 (1.49-1.65) | mosquitto 99% of one core | steal=1% idle=21% user+sys=49% |

| sweep | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 rate=100 pairs=16 | 1600 (1600-1600) | 1601 (1601-1604) | 0 (0-0) | 7.5 (6.8-9.7) | 45.2 (44.2-74.9) | 0 (0-0) | 0.29 (0.28-0.29) | mosquitto 34% of one core | steal=8% idle=74% user+sys=7% |
| qos=0 payload=64 rate=300 pairs=16 | 4800 (4800-4800) | 4800 (4798-4801) | 0 (0-0) | 11.0 (10.8-11.8) | 44.2 (35.7-49.4) | 0 (0-0) | 0.42 (0.38-0.42) | mosquitto 39% of one core | steal=9% idle=63% user+sys=11% |
| qos=0 payload=64 rate=1000 pairs=16 | 16000 (16000-16000) | 16002 (16001-16002) | 0 (0-0) | 12.3 (11.8-12.6) | 94.7 (53.8-106.5) | 0 (0-0) | 0.68 (0.67-0.68) | mosquitto 64% of one core | steal=10% idle=63% user+sys=9% |
| qos=1 payload=64 rate=100 pairs=16 | 1600 (1600-1600) | 1600 (1600-1602) | 1600 (1600-1602) | 7.4 (7.0-8.3) | 52.2 (42.0-87.2) | 0 (0-0) | 0.33 (0.30-0.33) | mosquitto 26% of one core | steal=7% idle=78% user+sys=6% |
| qos=1 payload=64 rate=300 pairs=16 | 4800 (4800-4800) | 4801 (4800-4802) | 4801 (4799-4801) | 11.0 (10.9-12.1) | 51.1 (46.0-121.2) | 0 (0-0) | 0.45 (0.41-0.47) | mosquitto 50% of one core | steal=6% idle=67% user+sys=11% |
| qos=1 payload=64 rate=1000 pairs=16 | 15778 (13741-16000) | 14272 (12811-14784) | 15773 (13711-15998) | 37.7 (14.4-179.9) | 2084.5 (2055.3-2138.9) | 0 (0-0) | 0.68 (0.63-0.71) | mosquitto 80% of one core | steal=5% idle=57% user+sys=20% |
| qos=0 payload=1024 rate=100 pairs=16 | 1600 (1600-1600) | 1600 (1600-1600) | 0 (0-0) | 18.9 (14.7-25.1) | 137.1 (46.4-140.5) | 0 (0-0) | 0.29 (0.28-0.29) | mosquitto 33% of one core | steal=8% idle=75% user+sys=5% |
| qos=0 payload=1024 rate=300 pairs=16 | 4800 (4800-4801) | 4801 (4798-4855) | 0 (0-0) | 11.1 (10.5-16.8) | 73.1 (43.6-126.0) | 0 (0-0) | 0.47 (0.46-0.48) | mosquitto 50% of one core | steal=9% idle=65% user+sys=11% |

| single-flow | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=1024 | 11970 (7747-16052) | 11978 (7739-16057) | 0 (0-0) | 214.6 (154.3-861.3) | 532.0 (325.0-1183.7) | 0 (0-0) | 0.22 (0.17-0.25) | mosquitto 67% of one core | steal=7% idle=70% user+sys=4% |
| qos=0 payload=64 | 50780 (48276-53327) | 50743 (48134-53358) | 0 (0-0) | 343.5 (227.8-378.8) | 426.1 (295.3-455.0) | 0 (0-0) | 0.27 (0.26-0.27) | mosquitto 100% of one core | steal=7% idle=74% user+sys=5% |
| qos=1 payload=64 | 2306 (1062-2527) | 1064 (539-1303) | 2306 (1062-2527) | 801.1 (12.1-1900.1) | 843.3 (25.1-2226.3) | 0 (0-0) | 0.07 (0.07-0.09) | mosquitto 9% of one core | steal=4% idle=91% user+sys=2% |

| latency | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=8 rate=100 | 800 (800-800) | 800 (800-801) | 0 (0-0) | 6.3 (6.1-7.8) | 47.8 (28.3-77.2) | 0 (0-0) | 0.19 (0.19-0.21) | mosquitto 15% of one core | steal=7% idle=73% user+sys=9% |
| qos=1 payload=64 pairs=8 rate=100 | 800 (800-800) | 800 (800-800) | 800 (800-800) | 6.6 (6.4-6.7) | 29.7 (29.5-65.8) | 0 (0-0) | 0.21 (0.20-0.22) | mosquitto 16% of one core | steal=7% idle=79% user+sys=5% |

| fanout | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 subs=100 rate=50 | 50 (50-50) | 5000 (5000-5001) | 0 (0-0) | 8.9 (8.8-9.2) | 39.7 (24.7-44.0) | 0 (0-0) | 0.23 (0.20-0.23) | mosquitto 19% of one core | steal=7% idle=80% user+sys=5% |
| qos=0 subs=1000 rate=10 | 10 (10-10) | 10000 (10000-10000) | 0 (0-0) | 22.1 (21.3-23.9) | 45.7 (43.0-48.2) | 0 (0-0) | 0.41 (0.38-0.45) | mosquitto 38% of one core | steal=6% idle=72% user+sys=7% |
| qos=1 subs=100 rate=50 | 50 (50-50) | 5000 (5000-5000) | 50 (50-50) | 9.1 (8.9-10.3) | 81.1 (33.5-82.8) | 0 (0-0) | 0.27 (0.25-0.28) | mosquitto 36% of one core | steal=7% idle=75% user+sys=7% |
| qos=0 subs=100 rate=0 | 1082 (949-1113) | 106268 (89172-108690) | 0 (0-0) | 4874.9 (4645.6-6940.4) | 5440.6 (5097.4-10271.9) | 0 (0-0) | 0.56 (0.55-0.58) | mosquitto 98% of one core | steal=7% idle=59% user+sys=10% |

| idle connections | broker clients | broker memory (bytes) | detail |
|---|---|---|---|
| baseline | 1 | 838232 |  37488 |
| 5000 | 5001 | 4903720 | IDLE opened_in=10s errors=0 first: ; IDLE generator_rss_kb=59452 generator_threads=1; loadgen: hold: 5000 of 5000 connections established in 9.3 s 144624 |
| after close | 1 | 838216 |  144624 |
| 10000 | 10001 | 8969960 | IDLE progress t=20s vps: TCP:   10013 (estab 10001, closed 1, orphaned 1, timewait 0) 43.3 278640 ; IDLE opened_in=20s errors=0 first: ; IDLE generator_rss_kb=1 278768 |
| after close | 1 | 838200 |  278768 |
| 20000 | 20001 | 17111240 | IDLE progress t=20s vps: TCP:   10749 (estab 10738, closed 1, orphaned 1, timewait 0) 39.8 299632 ; IDLE progress t=40s vps: TCP:   17908 (estab 17896, closed 1 546544 |
| after close | 1 | 838296 |  546404 |


### results/netcup-urmqtt-v042.txt

| handshake | conn/s | errors | p50 ms | p99 ms | TLS p50 ms | gen cpu | broker busy % (cores, first 14 s) |
|---|---|---|---|---|---|---|---|
| threads=32 | 423 (396-432) | 0 (0-0) | 57 (49-60) | 330 (288-1032) | 28 (24-29) | 0.83 (0.79-0.86) | c0=38 c1=29 |
| threads=64 | 526 (506-822) | 0 (0-0) | 79 (57-103) | 353 (275-788) | 37 (28-48) | 1.15 (1.07-1.26) | c0=17 c1=10 |
| threads=128 | 923 (834-1156) | 0 (0-0) | 114 (85-121) | 420 (390-499) | 56 (43-60) | 1.07 (0.99-1.31) | c0=14 c1=2 |

| throughput | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=16 | 187040 (182799-189100) | 46545 (45229-50940) | 0 (0-0) | 924.3 (799.5-1008.4) | 3131.1 (2269.5-3342.2) | 0 (0-0) | 1.26 (1.26-1.27) | c0=100 c1=2 | steal=0% idle=66% user+sys=21% |
| qos=0 payload=1024 pairs=16 | 21730 (21491-22100) | 12616 (11244-13878) | 0 (0-0) | 415.6 (353.9-418.1) | 1008.4 (939.1-1126.0) | 0 (0-0) | 1.00 (0.97-1.01) | c0=91 c1=2 | steal=0% idle=69% user+sys=18% |
| qos=1 payload=64 pairs=16 | 36012 (30479-42518) | 17463 (17224-19055) | 36012 (30479-42521) | 50.0 (45.7-50.5) | 258.9 (251.4-288.0) | 0 (0-0) | 1.06 (1.01-1.08) | c0=20 c1=2 | steal=0% idle=71% user+sys=20% |
| qos=1 payload=1024 pairs=16 | 20737 (19900-21268) | 8659 (6781-9809) | 20737 (19900-21268) | 85.6 (82.8-107.9) | 659.6 (517.1-752.9) | 0 (0-0) | 1.02 (1.00-1.02) | c0=17 c1=2 | steal=0% idle=69% user+sys=19% |
| qos=1 payload=64 pairs=64 | 101726 (92143-103329) | 51845 (50426-53869) | 101717 (92145-103336) | 66.9 (64.1-69.5) | 302.5 (278.4-308.8) | 0 (0-0) | 1.98 (1.97-1.98) | c0=84 c1=2 | steal=0% idle=48% user+sys=35% |

| sweep | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 rate=100 pairs=16 | 1600 (1590-1601) | 1600 (1591-1601) | 0 (0-0) | 15.8 (15.7-19.9) | 108.0 (95.3-184.4) | 0 (0-0) | 0.88 (0.88-0.89) | c0=36 c1=2 | steal=0% idle=75% user+sys=19% |
| qos=0 payload=64 rate=300 pairs=16 | 4802 (4780-4804) | 4809 (4753-4874) | 0 (0-0) | 17.6 (12.7-25.2) | 180.9 (148.2-204.1) | 0 (0-0) | 0.94 (0.89-0.94) | c0=30 c1=3 | steal=0% idle=74% user+sys=17% |
| qos=0 payload=64 rate=1000 pairs=16 | 15933 (15803-16007) | 15911 (15824-16012) | 0 (0-0) | 18.1 (15.9-18.4) | 136.7 (116.6-153.4) | 0 (0-0) | 1.01 (0.99-1.04) | c0=10 c1=3 | steal=0% idle=72% user+sys=19% |
| qos=1 payload=64 rate=100 pairs=16 | 1594 (1580-1600) | 1594 (1579-1602) | 1594 (1578-1602) | 15.3 (13.2-16.4) | 142.4 (134.8-269.6) | 0 (0-0) | 0.86 (0.86-0.91) | c0=36 c1=2 | steal=0% idle=75% user+sys=17% |
| qos=1 payload=64 rate=300 pairs=16 | 4800 (4799-4802) | 4792 (4791-4803) | 4799 (4796-4803) | 14.0 (13.5-15.7) | 100.0 (74.9-106.3) | 0 (0-0) | 0.93 (0.91-0.95) | c0=42 c1=2 | steal=0% idle=73% user+sys=18% |
| qos=1 payload=64 rate=1000 pairs=16 | 15380 (14947-15552) | 12952 (12677-13792) | 15384 (14948-15577) | 35.7 (32.0-45.5) | 274.2 (262.3-289.9) | 0 (0-0) | 1.05 (1.04-1.09) | c0=40 c1=4 | steal=0% idle=70% user+sys=20% |
| qos=0 payload=1024 rate=100 pairs=16 | 1599 (1599-1600) | 1596 (1594-1599) | 0 (0-0) | 18.6 (17.5-23.3) | 160.1 (134.8-250.4) | 0 (0-0) | 0.81 (0.80-0.94) | c0=16 c1=3 | steal=0% idle=78% user+sys=16% |
| qos=0 payload=1024 rate=300 pairs=16 | 4799 (4774-4819) | 4786 (4742-4843) | 0 (0-0) | 26.7 (20.9-45.3) | 429.0 (277.5-516.7) | 0 (0-0) | 0.91 (0.82-0.94) | c0=24 c1=2 | steal=0% idle=77% user+sys=15% |

| single-flow | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=1024 | 15544 (11499-17594) | 2732 (450-3832) | 0 (0-0) | 193.7 (96.3-219.6) | 1118.6 (688.2-9823.9) | 0 (0-0) | 0.69 (0.50-0.72) | c0=16 c1=2 | steal=0% idle=78% user+sys=13% |
| qos=0 payload=64 | 184222 (160908-195568) | 11806 (10005-14930) | 0 (0-0) | 274.7 (265.5-279.7) | 1600.2 (1167.8-2745.4) | 0 (0-0) | 0.95 (0.89-0.97) | c0=49 c1=2 | steal=0% idle=72% user+sys=18% |
| qos=1 payload=64 | 2266 (1232-2593) | 1245 (1085-1258) | 2266 (1231-2593) | 43.6 (41.3-46.3) | 244.8 (226.9-251.7) | 0 (0-0) | 0.58 (0.53-0.59) | c0=34 c1=2 | steal=0% idle=84% user+sys=13% |

| latency | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=8 rate=100 | 800 (799-800) | 800 (800-800) | 0 (0-0) | 8.2 (7.7-9.2) | 58.9 (56.2-70.0) | 0 (0-0) | 0.54 (0.50-0.74) | c0=30 c1=3 | steal=0% idle=88% user+sys=10% |
| qos=1 payload=64 pairs=8 rate=100 | 800 (800-800) | 800 (800-801) | 800 (800-801) | 8.5 (7.8-8.8) | 53.9 (51.2-125.2) | 0 (0-0) | 0.58 (0.53-0.64) | c0=17 c1=3 | steal=0% idle=84% user+sys=12% |

| fanout | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 subs=100 rate=50 | 50 (50-50) | 5000 (4992-5004) | 0 (0-0) | 11.0 (10.3-15.3) | 117.0 (94.9-214.1) | 0 (0-0) | 0.34 (0.25-0.56) | c0=18 c1=2 | steal=0% idle=94% user+sys=4% |
| qos=0 subs=1000 rate=10 | 10 (10-10) | 8192 (7283-8758) | 0 (0-0) | 226.6 (208.9-230.3) | 5811.2 (5720.0-5880.5) | 0 (0-0) | 0.38 (0.34-0.50) | c0=34 c1=2 | steal=0% idle=89% user+sys=6% |
| qos=1 subs=100 rate=50 | 50 (50-50) | 5000 (4999-5022) | 50 (50-50) | 14.4 (12.1-22.6) | 125.2 (117.6-176.5) | 0 (0-0) | 0.54 (0.49-0.57) | c0=24 c1=5 | steal=0% idle=85% user+sys=9% |
| qos=0 subs=100 rate=0 | 86834 (86437-89009) | 105105 (102406-122775) | 0 (0-0) | 1862.6 (1599.5-1927.9) | 4571.9 (4217.2-5412.5) | 0 (0-0) | 0.70 (0.66-0.73) | c0=21 c1=2 | steal=0% idle=80% user+sys=10% |

| idle connections | broker clients | broker memory (bytes) | detail |
|---|---|---|---|
| baseline | 101 | 2519552 |   |
| 5000 | 5000 | 3772416 | IDLE opened_in=9s errors=0 first: ; IDLE generator_rss_kb=57660 generator_threads=1; loadgen: hold: 5000 of 5000 connections established in 7.8 s  |
| after close | 1 | 1436672 |   |
| 10000 | 10001 | 5956096 | IDLE opened_in=15s errors=0 first: ; IDLE generator_rss_kb=105412 generator_threads=1; loadgen: hold: 10000 of 10000 connections established in 13.9 s  |
| after close | 0 | 1485824 |   |
| 20000 | 20001 | 10695680 | IDLE opened_in=50s errors=0 first: ; IDLE generator_rss_kb=204676 generator_threads=1; loadgen: hold: 20000 of 20000 connections established in 48.9 s  |
| after close | 0 | 1985536 |   |


### results/netcup-urmqtt-sack.txt

| handshake | conn/s | errors | p50 ms | p99 ms | TLS p50 ms | gen cpu | broker busy % (cores, first 14 s) |
|---|---|---|---|---|---|---|---|
| threads=32 | 269 (257-356) | 0 (0-0) | 76 (59-82) | 1086 (1074-1137) | 35 (28-39) | 0.87 (0.77-0.92) | c0=52 c1=47 |
| threads=64 | 553 (496-695) | 0 (0-0) | 64 (57-84) | 1099 (1071-1112) | 30 (27-41) | 1.08 (1.05-1.18) | c0=39 c1=32 |
| threads=128 | 820 (646-857) | 0 (0-0) | 94 (87-106) | 1154 (1153-1180) | 44 (40-49) | 1.29 (1.09-1.40) | c0=11 c1=4 |

| throughput | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=16 | 182647 (178165-190363) | 43692 (39515-69077) | 0 (0-0) | 1073.5 (712.1-1152.5) | 2504.3 (1400.2-2618.5) | 0 (0-0) | 1.45 (1.41-1.52) | c0=2 c1=2 | steal=0% idle=61% user+sys=22% |
| qos=0 payload=1024 pairs=16 | 20675 (20101-21746) | 12443 (11345-12859) | 0 (0-0) | 311.8 (278.3-336.6) | 916.1 (844.3-995.0) | 0 (0-0) | 1.05 (1.01-1.06) | c0=100 c1=2 | steal=0% idle=69% user+sys=18% |
| qos=1 payload=64 pairs=16 | 26369 (23665-27645) | 14056 (13495-14738) | 26369 (23663-27648) | 41.2 (41.0-57.2) | 280.8 (279.3-305.6) | 0 (0-0) | 0.98 (0.92-1.07) | c0=38 c1=3 | steal=0% idle=68% user+sys=22% |
| qos=1 payload=1024 pairs=16 | 13220 (12539-13799) | 5774 (5409-6080) | 13220 (12539-13799) | 100.9 (92.1-125.9) | 826.1 (750.4-845.9) | 0 (0-0) | 1.01 (1.01-1.03) | c0=19 c1=2 | steal=0% idle=70% user+sys=19% |
| qos=1 payload=64 pairs=64 | 73815 (72336-82695) | 42448 (40783-43870) | 73810 (72333-82680) | 56.3 (54.5-58.2) | 302.2 (297.4-406.4) | 0 (0-0) | 1.98 (1.97-1.98) | c0=2 c1=2 | steal=0% idle=48% user+sys=36% |

| sweep | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 rate=100 pairs=16 | 1601 (1600-1602) | 1600 (1597-1604) | 0 (0-0) | 12.1 (10.6-14.6) | 278.8 (275.5-320.4) | 0 (0-0) | 0.74 (0.73-0.81) | c0=19 c1=2 | steal=0% idle=76% user+sys=17% |
| qos=0 payload=64 rate=300 pairs=16 | 4800 (4799-4801) | 4795 (4781-4840) | 0 (0-0) | 15.2 (11.3-15.6) | 244.8 (241.6-405.1) | 0 (0-0) | 0.79 (0.78-0.80) | c0=49 c1=2 | steal=0% idle=75% user+sys=17% |
| qos=0 payload=64 rate=1000 pairs=16 | 15998 (15933-16000) | 15929 (15913-16005) | 0 (0-0) | 11.6 (9.9-18.8) | 238.3 (222.6-372.2) | 0 (0-0) | 0.99 (0.96-1.00) | c0=52 c1=3 | steal=0% idle=73% user+sys=17% |
| qos=1 payload=64 rate=100 pairs=16 | 1586 (1582-1597) | 1593 (1583-1597) | 1590 (1582-1597) | 11.4 (10.8-13.2) | 407.3 (240.7-528.4) | 0 (0-0) | 0.78 (0.67-0.82) | c0=22 c1=3 | steal=0% idle=74% user+sys=19% |
| qos=1 payload=64 rate=300 pairs=16 | 4567 (4494-4600) | 4427 (4392-4518) | 4576 (4498-4606) | 22.0 (21.4-25.5) | 410.6 (299.2-515.0) | 0 (0-0) | 0.92 (0.90-0.94) | c0=13 c1=2 | steal=0% idle=72% user+sys=19% |
| qos=1 payload=64 rate=1000 pairs=16 | 11327 (10215-11337) | 8799 (8146-8869) | 11332 (10206-11340) | 32.5 (29.9-42.2) | 308.2 (283.3-591.1) | 0 (0-0) | 1.03 (0.97-1.03) | c0=47 c1=2 | steal=0% idle=70% user+sys=21% |
| qos=0 payload=1024 rate=100 pairs=16 | 1600 (1600-1600) | 1600 (1599-1601) | 0 (0-0) | 9.4 (9.3-10.2) | 194.4 (71.9-209.4) | 0 (0-0) | 0.73 (0.69-0.77) | c0=41 c1=2 | steal=0% idle=78% user+sys=17% |
| qos=0 payload=1024 rate=300 pairs=16 | 4800 (4799-4801) | 4773 (4757-4791) | 0 (0-0) | 13.9 (12.8-15.8) | 217.7 (189.6-366.0) | 0 (0-0) | 0.82 (0.81-0.86) | c0=40 c1=3 | steal=0% idle=78% user+sys=14% |

| single-flow | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=1024 | 18568 (12370-19217) | 2134 (99-2963) | 0 (0-0) | 220.1 (156.9-3042.3) | 521.4 (416.4-5848.2) | 0 (0-0) | 0.44 (0.41-0.52) | c0=48 c1=2 | steal=0% idle=84% user+sys=10% |
| qos=0 payload=64 | 152858 (148883-188067) | 22289 (13170-24581) | 0 (0-0) | 233.5 (161.3-311.4) | 568.5 (408.8-1096.3) | 0 (0-0) | 0.85 (0.82-0.89) | c0=100 c1=2 | steal=0% idle=74% user+sys=16% |
| qos=1 payload=64 | 1568 (1101-1847) | 938 (807-958) | 1565 (1101-1848) | 39.0 (33.5-40.9) | 250.4 (248.8-250.5) | 0 (0-0) | 0.28 (0.25-0.36) | c0=12 c1=2 | steal=0% idle=92% user+sys=6% |

| latency | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=8 rate=100 | 800 (800-801) | 799 (799-805) | 0 (0-0) | 15.7 (15.6-19.2) | 218.4 (217.9-370.8) | 0 (0-0) | 0.70 (0.69-0.83) | c0=33 c1=2 | steal=0% idle=74% user+sys=19% |
| qos=1 payload=64 pairs=8 rate=100 | 797 (797-801) | 800 (796-806) | 800 (789-809) | 12.5 (11.3-13.6) | 221.3 (214.9-223.5) | 0 (0-0) | 0.82 (0.69-0.84) | c0=31 c1=3 | steal=0% idle=75% user+sys=18% |

| fanout | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 subs=100 rate=50 | 50 (50-50) | 5009 (4934-5032) | 0 (0-0) | 13.4 (12.8-20.5) | 564.6 (491.6-570.3) | 0 (0-0) | 0.32 (0.29-0.37) | c0=11 c1=2 | steal=0% idle=88% user+sys=8% |
| qos=0 subs=1000 rate=10 | 10 (10-10) | 8639 (7779-8971) | 0 (0-0) | 221.8 (207.6-232.1) | 5816.8 (3734.9-5832.6) | 0 (0-0) | 0.53 (0.44-0.59) | c0=38 c1=20 | steal=0% idle=85% user+sys=8% |
| qos=1 subs=100 rate=50 | 50 (50-50) | 5013 (5010-5054) | 50 (50-50) | 12.7 (12.6-13.4) | 381.0 (333.0-874.9) | 0 (0-0) | 0.47 (0.43-0.48) | c0=40 c1=3 | steal=0% idle=84% user+sys=10% |
| qos=0 subs=100 rate=0 | 84453 (69440-84754) | 124314 (123122-150698) | 0 (0-0) | 1361.3 (1257.7-1579.4) | 4389.8 (4103.9-4794.6) | 0 (0-0) | 0.91 (0.87-0.99) | c0=45 c1=5 | steal=0% idle=70% user+sys=14% |

| idle connections | broker clients | broker memory (bytes) | detail |
|---|---|---|---|
| baseline | 0 | 2190336 |   |
| 5000 | 5000 | 3661824 | IDLE opened_in=12s errors=0 first: ; IDLE generator_rss_kb=57852 generator_threads=1; loadgen: hold: 5000 of 5000 connections established in 11.4 s  |
| after close | 1 | 1522688 |   |
| 10000 | 10000 | 6058496 | IDLE opened_in=21s errors=0 first: ; IDLE generator_rss_kb=105864 generator_threads=1; loadgen: hold: 10000 of 10000 connections established in 20.2 s  |
| after close | 1 | 2406912 |   |
| 20000 | 20001 | 10822144 | IDLE opened_in=62s errors=0 first: ; IDLE generator_rss_kb=204808 generator_threads=1; loadgen: hold: 20000 of 20000 connections established in 61.0 s  |
| after close | 0 | 1554944 |   |


### results/netcup-mosquitto.txt

| handshake | conn/s | errors | p50 ms | p99 ms | TLS p50 ms | gen cpu | broker busy % (cores, first 14 s) |
|---|---|---|---|---|---|---|---|
| threads=32 | 264 (252-286) | 0 (0-0) | 100 (95-111) | 328 (317-338) | 77 (75-85) | 0.55 (0.53-0.62) | mosquitto 66% of one core |
| threads=64 | 409 (328-419) | 0 (0-0) | 142 (138-152) | 368 (330-1141) | 101 (99-108) | 0.76 (0.75-0.91) | mosquitto 90% of one core |
| threads=128 | 419 (411-425) | 0 (0-0) | 281 (280-291) | 603 (481-1240) | 194 (191-205) | 0.99 (0.86-1.04) | mosquitto 94% of one core |

| throughput | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=16 | 59589 (58425-60209) | 57920 (57021-59272) | 0 (0-0) | 1219.7 (1145.2-1306.1) | 1660.8 (1576.6-3113.3) | 0 (0-0) | 1.28 (1.24-1.28) | mosquitto 99% of one core | steal=0% idle=64% user+sys=21% |
| qos=0 payload=1024 pairs=16 | 20840 (13732-21531) | 14767 (10199-15351) | 0 (0-0) | 1382.3 (1341.6-1443.4) | 2587.5 (2376.5-4626.8) | 0 (0-0) | 1.11 (1.11-1.16) | mosquitto 58% of one core | steal=0% idle=69% user+sys=18% |
| qos=1 payload=64 pairs=16 | 23248 (19883-23463) | 14805 (13749-15906) | 23247 (19884-23463) | 789.0 (672.0-1041.3) | 2051.4 (1529.8-2408.0) | 0 (0-0) | 1.03 (1.01-1.05) | mosquitto 67% of one core | steal=0% idle=72% user+sys=20% |
| qos=1 payload=1024 pairs=16 | 15795 (13423-17208) | 14274 (11159-15764) | 15796 (13423-17208) | 478.8 (244.8-847.1) | 1700.4 (1328.3-2795.1) | 0 (0-0) | 1.13 (1.12-1.14) | mosquitto 82% of one core | steal=0% idle=68% user+sys=20% |
| qos=1 payload=64 pairs=64 | 20139 (20051-24837) | 20142 (20082-24825) | 20139 (20052-24836) | 108.7 (89.1-110.5) | 319.4 (304.6-322.3) | 0 (0-0) | 1.99 (1.99-1.99) | mosquitto 98% of one core | steal=0% idle=50% user+sys=35% |

| sweep | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 rate=100 pairs=16 | 1600 (1599-1600) | 1600 (1599-1600) | 0 (0-0) | 14.3 (11.1-14.7) | 150.0 (148.2-151.3) | 0 (0-0) | 0.70 (0.62-0.76) | mosquitto 15% of one core | steal=0% idle=82% user+sys=14% |
| qos=0 payload=64 rate=300 pairs=16 | 4800 (4800-4800) | 4801 (4799-4803) | 0 (0-0) | 13.0 (12.8-13.8) | 58.5 (57.0-58.8) | 0 (0-0) | 0.80 (0.80-0.80) | mosquitto 27% of one core | steal=0% idle=79% user+sys=16% |
| qos=0 payload=64 rate=1000 pairs=16 | 16016 (15999-16048) | 16035 (16004-16107) | 0 (0-0) | 18.8 (14.4-19.7) | 68.6 (61.9-85.4) | 0 (0-0) | 0.99 (0.96-0.99) | mosquitto 50% of one core | steal=0% idle=74% user+sys=17% |
| qos=1 payload=64 rate=100 pairs=16 | 1600 (1600-1600) | 1601 (1600-1605) | 1600 (1599-1602) | 16.4 (15.2-18.2) | 151.8 (128.3-167.8) | 0 (0-0) | 0.83 (0.81-0.87) | mosquitto 18% of one core | steal=0% idle=77% user+sys=18% |
| qos=1 payload=64 rate=300 pairs=16 | 4806 (4801-4806) | 4805 (4777-4814) | 4821 (4813-4821) | 24.8 (21.0-25.2) | 225.1 (212.8-247.3) | 0 (0-0) | 0.92 (0.91-0.94) | mosquitto 30% of one core | steal=0% idle=74% user+sys=19% |
| qos=1 payload=64 rate=1000 pairs=16 | 14843 (14552-15366) | 12977 (12103-13621) | 14843 (14532-15361) | 526.9 (353.7-904.9) | 2588.5 (2478.0-2897.8) | 0 (0-0) | 1.03 (0.97-1.04) | mosquitto 59% of one core | steal=0% idle=73% user+sys=18% |
| qos=0 payload=1024 rate=100 pairs=16 | 1600 (1599-1600) | 1598 (1598-1601) | 0 (0-0) | 15.0 (13.1-15.6) | 47.1 (45.7-58.0) | 0 (0-0) | 0.74 (0.70-0.75) | mosquitto 13% of one core | steal=0% idle=78% user+sys=16% |
| qos=0 payload=1024 rate=300 pairs=16 | 4800 (4800-4800) | 4802 (4783-4805) | 0 (0-0) | 16.5 (13.1-16.7) | 90.2 (78.2-244.5) | 0 (0-0) | 0.85 (0.83-0.87) | mosquitto 34% of one core | steal=0% idle=78% user+sys=14% |

| single-flow | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=1024 | 17687 (11930-20491) | 6109 (3358-6870) | 0 (0-0) | 562.1 (502.5-719.9) | 1110.4 (933.7-1952.2) | 0 (0-0) | 0.71 (0.62-0.81) | mosquitto 42% of one core | steal=0% idle=81% user+sys=13% |
| qos=0 payload=64 | 59884 (54459-67898) | 48660 (33932-51942) | 0 (0-0) | 639.7 (347.0-1105.7) | 878.2 (555.5-1177.5) | 0 (0-0) | 0.93 (0.87-0.97) | mosquitto 95% of one core | steal=0% idle=77% user+sys=14% |
| qos=1 payload=64 | 1623 (960-2028) | 959 (458-1280) | 1623 (960-2028) | 847.3 (21.9-2258.6) | 1177.7 (54.5-2484.7) | 0 (0-0) | 0.33 (0.29-0.37) | mosquitto 8% of one core | steal=0% idle=93% user+sys=5% |

| latency | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=8 rate=100 | 800 (800-800) | 798 (798-800) | 0 (0-0) | 8.2 (7.9-11.7) | 139.9 (128.1-157.1) | 0 (0-0) | 0.60 (0.56-0.64) | mosquitto 9% of one core | steal=0% idle=84% user+sys=13% |
| qos=1 payload=64 pairs=8 rate=100 | 800 (800-800) | 800 (797-804) | 798 (797-804) | 12.8 (8.6-20.6) | 136.2 (110.6-145.7) | 0 (0-0) | 0.67 (0.63-0.81) | mosquitto 12% of one core | steal=0% idle=83% user+sys=13% |

| fanout | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 subs=100 rate=50 | 50 (50-50) | 5010 (4996-5023) | 0 (0-0) | 13.6 (12.1-21.9) | 150.4 (118.2-197.0) | 0 (0-0) | 0.58 (0.50-0.69) | mosquitto 17% of one core | steal=0% idle=86% user+sys=9% |
| qos=0 subs=1000 rate=10 | 9 (9-10) | 9841 (9627-10001) | 0 (0-0) | 55.5 (31.9-65.1) | 475.9 (109.6-528.6) | 0 (0-0) | 0.91 (0.60-0.96) | mosquitto 42% of one core | steal=0% idle=81% user+sys=9% |
| qos=1 subs=100 rate=50 | 50 (50-50) | 4995 (4992-5025) | 50 (50-50) | 15.1 (13.3-18.4) | 172.2 (135.6-242.9) | 0 (0-0) | 0.73 (0.66-0.78) | mosquitto 27% of one core | steal=0% idle=81% user+sys=12% |
| qos=0 subs=100 rate=0 | 865 (822-932) | 85806 (81012-91917) | 0 (0-0) | 2722.6 (2717.9-3350.8) | 3172.9 (3170.1-3717.7) | 0 (0-0) | 0.84 (0.83-0.98) | mosquitto 97% of one core | steal=0% idle=76% user+sys=13% |

| idle connections | broker clients | broker memory (bytes) | detail |
|---|---|---|---|
| baseline | 1 | 838344 |  37232 |
| 5000 | 5001 | 4903672 | IDLE opened_in=13s errors=0 first: ; IDLE generator_rss_kb=59768 generator_threads=1; loadgen: hold: 5000 of 5000 connections established in 12.2 s 144080 |
| after close | 1 | 838376 |  144080 |
| 10000 | 10001 | 8969784 | IDLE progress t=20s vps: TCP:   9090 (estab 9089, closed 1, orphaned 0, timewait 0) 26.8 253628 ; IDLE opened_in=23s errors=0 first: ; IDLE generator_rss_kb=110 277892 |
| after close | 1 | 838344 |  277892 |
| 20000 | 20001 | 17110632 | IDLE progress t=20s vps: TCP:   9037 (estab 9032, closed 1, orphaned 0, timewait 0) 26.0 277892 ; IDLE progress t=40s vps: TCP:   16046 (estab 16041, closed 1,  546008 |
| after close | 1 | 838264 |  545744 |


### results/contabo-urmqtt-v042.txt

| throughput | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=16 | 171758 (140691-176236) | 131775 (130977-132105) | 0 (0-0) | 1270.5 (376.9-1285.3) | 3122.8 (1962.6-3746.2) | 0 (0-0) | 1.25 (1.23-1.49) | c0=30 c1=43 c2=46 c3=41 | steal=21% idle=46% user+sys=23% |
| qos=0 payload=1024 pairs=16 | 14913 (14722-16186) | 14403 (14241-15999) | 0 (0-0) | 862.6 (856.2-1041.8) | 2118.4 (1809.0-4558.0) | 0 (0-0) | 0.85 (0.83-0.86) | c0=41 c1=41 c2=47 c3=25 | steal=26% idle=48% user+sys=17% |

| sweep | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 rate=1000 pairs=16 | 16000 (16000-16000) | 15997 (15968-16003) | 0 (0-0) | 11.6 (9.3-12.3) | 52.6 (48.2-134.3) | 0 (0-0) | 0.71 (0.67-0.77) | c0=33 c1=28 c2=27 c3=45 | steal=38% idle=45% user+sys=13% |

| single-flow | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 | 48932 (24293-93247) | 33898 (17197-57396) | 0 (0-0) | 550.5 (157.1-1547.7) | 978.9 (355.1-2454.5) | 0 (0-0) | 0.30 (0.20-0.38) | c0=20 c1=9 c2=16 c3=36 | steal=10% idle=73% user+sys=13% |
| qos=0 payload=1024 | 7670 (5683-8623) | 4330 (3454-5081) | 0 (0-0) | 157.4 (118.2-303.8) | 441.2 (337.4-669.1) | 0 (0-0) | 0.17 (0.16-0.18) | c0=30 c1=20 c2=13 c3=36 | steal=24% idle=62% user+sys=11% |
| qos=1 payload=64 | 4496 (4455-5365) | 1933 (1232-2226) | 4496 (4455-5365) | 33.5 (29.7-56.5) | 149.5 (112.3-182.4) | 0 (0-0) | 0.13 (0.12-0.13) | c0=18 c1=5 c2=5 c3=35 | steal=7% idle=80% user+sys=11% |


### results/contabo-urmqtt-sack.txt

| throughput | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=16 | 118802 (108880-149320) | 94475 (76276-141204) | 0 (0-0) | 646.0 (401.4-648.0) | 1701.3 (979.4-2210.5) | 0 (0-0) | 1.17 (1.07-1.24) | c0=37 c1=43 c2=46 c3=42 | steal=17% idle=47% user+sys=25% |
| qos=0 payload=1024 pairs=16 | 15084 (12936-15948) | 14968 (12850-15722) | 0 (0-0) | 429.6 (263.3-476.8) | 1142.8 (674.1-1517.2) | 0 (0-0) | 0.90 (0.80-0.95) | c0=18 c1=9 c2=9 c3=35 | steal=10% idle=56% user+sys=23% |

| sweep | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 rate=1000 pairs=16 | 16001 (16000-16002) | 15996 (15989-16010) | 0 (0-0) | 10.0 (6.8-18.4) | 172.6 (111.0-462.1) | 0 (0-0) | 0.70 (0.65-0.82) | c0=11 c1=10 c2=25 c3=28 | steal=30% idle=49% user+sys=15% |

| single-flow | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 | 72908 (42069-83377) | 48044 (19559-75682) | 0 (0-0) | 297.2 (105.9-856.0) | 628.8 (198.8-1167.7) | 0 (0-0) | 0.38 (0.25-0.41) | c0=34 c1=71 c2=40 c3=21 | steal=15% idle=67% user+sys=13% |
| qos=0 payload=1024 | 7026 (4115-8505) | 5497 (3826-7851) | 0 (0-0) | 211.5 (73.3-541.8) | 477.9 (182.4-857.9) | 0 (0-0) | 0.18 (0.17-0.23) | c0=31 c1=13 c2=20 c3=18 | steal=14% idle=72% user+sys=11% |
| qos=1 payload=64 | 4417 (4200-5404) | 2360 (1214-2474) | 4417 (4200-5404) | 29.1 (27.5-61.6) | 86.2 (66.0-114.1) | 0 (0-0) | 0.13 (0.13-0.14) | c0=28 c1=13 c2=12 c3=26 | steal=13% idle=75% user+sys=10% |


### results/contabo-mosquitto.txt

| handshake | conn/s | errors | p50 ms | p99 ms | TLS p50 ms | gen cpu | broker busy % (cores, first 14 s) |
|---|---|---|---|---|---|---|---|
| threads=32 | 147 (131-209) | 0 (0-0) | 176 (126-190) | 493 (408-796) | 114 (91-121) | 0.15 (0.12-0.20) | mosquitto 79% of one core |
| threads=64 | 294 (284-349) | 0 (0-0) | 176 (159-186) | 489 (442-1373) | 119 (109-123) | 0.24 (0.23-0.27) | mosquitto 84% of one core |
| threads=128 | 446 (364-502) | 0 (0-0) | 243 (227-309) | 835 (549-870) | 168 (153-194) | 0.43 (0.35-0.67) | mosquitto 91% of one core |

| throughput | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=16 | 47826 (37273-54572) | 47033 (36968-53645) | 0 (0-0) | 2902.7 (824.3-2914.1) | 5272.0 (2938.2-5476.1) | 0 (0-0) | 0.96 (0.90-0.97) | mosquitto 100% of one core | steal=24% idle=49% user+sys=21% |
| qos=0 payload=1024 pairs=16 | 13308 (11068-16670) | 13266 (10957-16831) | 0 (0-0) | 626.1 (350.6-683.9) | 1597.3 (1198.5-3423.7) | 0 (0-0) | 0.88 (0.85-0.94) | mosquitto 73% of one core | steal=17% idle=53% user+sys=20% |
| qos=1 payload=64 pairs=16 | 12623 (11739-14123) | 11088 (10621-12746) | 12623 (11739-14123) | 439.1 (384.4-697.8) | 2410.4 (1773.9-2957.6) | 0 (0-0) | 0.74 (0.71-0.75) | mosquitto 85% of one core | steal=24% idle=53% user+sys=18% |
| qos=1 payload=1024 pairs=16 | 10339 (9998-10518) | 10025 (9169-10121) | 10338 (9998-10518) | 170.6 (99.0-400.6) | 2327.5 (1227.9-2866.8) | 0 (0-0) | 0.83 (0.80-0.83) | mosquitto 78% of one core | steal=25% idle=50% user+sys=18% |
| qos=1 payload=64 pairs=64 | 12550 (11409-18887) | 12646 (11396-18867) | 12550 (11409-18887) | 173.6 (104.0-192.0) | 611.8 (446.3-687.6) | 0 (0-0) | 1.98 (1.95-1.99) | mosquitto 97% of one core | steal=39% idle=23% user+sys=27% |

| sweep | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 rate=100 pairs=16 | 1600 (1600-1600) | 1602 (1597-1602) | 0 (0-0) | 13.0 (7.9-18.0) | 149.8 (146.9-180.9) | 0 (0-0) | 0.43 (0.39-0.44) | mosquitto 39% of one core | steal=32% idle=50% user+sys=15% |
| qos=0 payload=64 rate=300 pairs=16 | 4800 (4800-4800) | 4798 (4794-4801) | 0 (0-0) | 10.5 (9.5-16.9) | 120.7 (66.9-166.1) | 0 (0-0) | 0.57 (0.56-0.59) | mosquitto 42% of one core | steal=15% idle=62% user+sys=17% |
| qos=0 payload=64 rate=1000 pairs=16 | 16001 (16000-16003) | 15997 (15803-16162) | 0 (0-0) | 33.6 (17.8-156.6) | 249.3 (190.2-1413.2) | 0 (0-0) | 0.67 (0.64-0.71) | mosquitto 65% of one core | steal=22% idle=54% user+sys=19% |
| qos=1 payload=64 rate=100 pairs=16 | 1600 (1593-1600) | 1602 (1597-1604) | 1604 (1598-1605) | 34.8 (14.9-91.3) | 308.0 (113.7-414.1) | 0 (0-0) | 0.43 (0.42-0.46) | mosquitto 57% of one core | steal=25% idle=54% user+sys=17% |
| qos=1 payload=64 rate=300 pairs=16 | 4802 (4678-4814) | 4798 (4686-4830) | 4841 (4682-4850) | 23.9 (18.1-30.5) | 246.9 (235.4-312.7) | 0 (0-0) | 0.59 (0.53-0.59) | mosquitto 69% of one core | steal=39% idle=45% user+sys=13% |
| qos=1 payload=64 rate=1000 pairs=16 | 13798 (9951-14947) | 13586 (9616-14218) | 13764 (9952-14976) | 114.8 (106.6-162.0) | 1833.9 (1809.2-2580.5) | 0 (0-0) | 0.79 (0.77-0.83) | mosquitto 85% of one core | steal=18% idle=56% user+sys=20% |
| qos=0 payload=1024 rate=100 pairs=16 | 1600 (1600-1601) | 1599 (1599-1602) | 0 (0-0) | 17.8 (14.1-19.6) | 176.2 (108.5-217.5) | 0 (0-0) | 0.44 (0.43-0.45) | mosquitto 38% of one core | steal=12% idle=68% user+sys=16% |
| qos=0 payload=1024 rate=300 pairs=16 | 4800 (4786-4800) | 4803 (4765-4812) | 0 (0-0) | 36.1 (16.2-53.1) | 239.0 (230.9-492.9) | 0 (0-0) | 0.59 (0.57-0.59) | mosquitto 72% of one core | steal=14% idle=62% user+sys=17% |

| single-flow | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=1024 | 6234 (4402-10221) | 6288 (4400-10196) | 0 (0-0) | 344.2 (87.6-613.8) | 1245.8 (363.8-1827.1) | 0 (0-0) | 0.17 (0.16-0.23) | mosquitto 79% of one core | steal=7% idle=78% user+sys=12% |
| qos=0 payload=64 | 39650 (29099-46594) | 39540 (29219-46571) | 0 (0-0) | 306.3 (142.3-602.6) | 619.2 (348.9-888.5) | 0 (0-0) | 0.32 (0.28-0.35) | mosquitto 98% of one core | steal=11% idle=71% user+sys=13% |
| qos=1 payload=64 | 1739 (1623-2223) | 770 (716-1330) | 1739 (1623-2226) | 1272.1 (700.4-1464.1) | 1661.9 (1139.8-2386.9) | 0 (0-0) | 0.11 (0.09-0.12) | mosquitto 33% of one core | steal=8% idle=79% user+sys=12% |

| latency | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 payload=64 pairs=8 rate=100 | 800 (800-800) | 799 (798-805) | 0 (0-0) | 11.2 (8.1-12.6) | 149.3 (110.1-173.6) | 0 (0-0) | 0.28 (0.26-0.31) | mosquitto 39% of one core | steal=20% idle=66% user+sys=12% |
| qos=1 payload=64 pairs=8 rate=100 | 800 (800-800) | 801 (800-801) | 800 (799-802) | 17.8 (10.4-30.6) | 148.6 (140.1-222.4) | 0 (0-0) | 0.31 (0.29-0.33) | mosquitto 42% of one core | steal=27% idle=59% user+sys=11% |

| fanout | published/s | delivered/s | acked/s | lat p50 ms | p99 ms | lost conns | gen cpu | broker busy | generator host |
|---|---|---|---|---|---|---|---|---|---|
| qos=0 subs=100 rate=50 | 50 (50-50) | 4985 (4981-5022) | 0 (0-0) | 16.8 (14.2-24.8) | 202.0 (198.0-322.7) | 0 (0-0) | 0.22 (0.18-0.24) | mosquitto 36% of one core | steal=24% idle=62% user+sys=10% |
| qos=0 subs=1000 rate=10 | 10 (10-10) | 10000 (9964-10003) | 0 (0-0) | 30.0 (27.5-44.0) | 316.5 (232.5-389.3) | 0 (0-0) | 0.41 (0.38-0.44) | mosquitto 52% of one core | steal=18% idle=65% user+sys=12% |
| qos=1 subs=100 rate=50 | 50 (50-50) | 4973 (4971-5017) | 50 (50-50) | 50.5 (46.9-144.4) | 299.4 (288.0-471.2) | 0 (0-0) | 0.35 (0.29-0.36) | mosquitto 61% of one core | steal=34% idle=54% user+sys=10% |
| qos=0 subs=100 rate=0 | 645 (517-667) | 59587 (52350-62137) | 0 (0-0) | 7116.0 (6742.6-7131.4) | 11128.8 (9798.9-11404.0) | 0 (0-0) | 0.40 (0.38-0.42) | mosquitto 96% of one core | steal=22% idle=61% user+sys=11% |

| idle connections | broker clients | broker memory (bytes) | detail |
|---|---|---|---|
| baseline | 1 | 838248 |  37744 |
| 5000 | 5001 | 4903416 | IDLE opened_in=15s errors=0 first: ; IDLE generator_rss_kb=60048 generator_threads=1; loadgen: hold: 5000 of 5000 connections established in 14.4 s 144624 |
| after close | 1 | 838200 |  144624 |
| 10000 | 10001 | 8969672 | IDLE progress t=20s vps: TCP:   9804 (estab 9793, closed 1, orphaned 0, timewait 0) 43.3 273008 ; IDLE opened_in=24s errors=0 first: ; IDLE generator_rss_kb=112 278384 |
| after close | 1 | 838200 |  278384 |
| 20000 | 20001 | 17110104 | IDLE progress t=20s vps: TCP:   8879 (estab 8868, closed 1, orphaned 0, timewait 0) 40.1 278384 ; IDLE progress t=40s vps: TCP:   15242 (estab 15231, closed 1,  546544 |
| after close | 1 | 1107416 |  546332 |


