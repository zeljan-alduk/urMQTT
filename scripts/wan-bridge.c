/* A delaying L2 bridge between a QEMU `-netdev dgram` socket and a Linux TAP
 * device (PERF, ADR-222). Run in a Linux container with NET_ADMIN and
 * /dev/net/tun; a load generator in the same container reaches the guest
 * through the tap, so the guest sees a real Linux TCP peer at a chosen
 * round-trip time, loss and bottleneck rate instead of QEMU's slirp proxy.
 *
 *   gcc -O2 -o wan-bridge wan-bridge.c
 *   wan-bridge LISTEN_PORT RTT_MS LOSS_PERCENT RATE_MBIT QUEUE_PKTS [tap0]
 *
 * One-way delay is RTT/2 in each direction. LOSS drops that percentage of
 * frames in each direction at random. RATE_MBIT (0 = unlimited) is a
 * bottleneck per direction with a drop-tail queue of QUEUE_PKTS frames.
 * Then: ip addr add 10.0.2.2/24 dev tap0 (done here), loadgen -> 10.0.2.15. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAXPKT 2048
struct pkt { uint64_t due; int len; unsigned char d[MAXPKT]; };
struct fifo { struct pkt *q; size_t cap, head, n; uint64_t last_tx; uint64_t dropped, sent; };

static uint64_t now_ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000000000ull + t.tv_nsec; }
static uint64_t rng = 88172645463325252ull;
static uint64_t xr(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

static void push(struct fifo *f, const unsigned char *d, int len, uint64_t due, size_t limit) {
    if (f->n >= limit || f->n >= f->cap) { f->dropped++; return; }
    struct pkt *p = &f->q[(f->head + f->n) % f->cap];
    p->due = due; p->len = len; memcpy(p->d, d, len);
    f->n++;
}

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: %s PORT RTT_MS LOSS_PCT RATE_MBIT QUEUE_PKTS [tap]\n", argv[0]); return 2; }
    int port = atoi(argv[1]);
    double rtt_ms = atof(argv[2]), loss = atof(argv[3]) / 100.0, rate = atof(argv[4]);
    size_t qlimit = (size_t)atol(argv[5]);
    const char *tapname = argc > 6 ? argv[6] : "tap0";
    uint64_t owd = (uint64_t)(rtt_ms * 500000.0);

    int tap = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI; strncpy(ifr.ifr_name, tapname, IFNAMSIZ - 1);
    if (tap < 0 || ioctl(tap, TUNSETIFF, &ifr) < 0) { perror("tap"); return 1; }
    char cmd[256];
    snprintf(cmd, sizeof cmd, "ip addr add 10.0.2.2/24 dev %s && ip link set %s txqueuelen 20000 up && ethtool -K %s tso off gso off gro off >/dev/null 2>&1", tapname, tapname, tapname);
    if (system(cmd) < 0) return 1;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    int big = 16 << 20; setsockopt(s, SOL_SOCKET, SO_RCVBUF, &big, sizeof big); setsockopt(s, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY};
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 1; }
    fcntl(s, F_SETFL, O_NONBLOCK);
    struct sockaddr_in qemu; socklen_t ql = sizeof qemu; int have_qemu = 0;

    size_t cap = 65536;
    struct fifo g2p = {.q = calloc(cap, sizeof(struct pkt)), .cap = cap}, p2g = {.q = calloc(cap, sizeof(struct pkt)), .cap = cap};
    if (!g2p.q || !p2g.q) return 1;
    uint64_t lastlog = now_ns();
    unsigned char buf[MAXPKT];
    for (;;) {
        uint64_t now = now_ns();
        uint64_t next = now + 1000000000ull;
        struct fifo *fs[2] = {&g2p, &p2g};
        for (int i = 0; i < 2; i++) if (fs[i]->n) { uint64_t d = fs[i]->q[fs[i]->head].due; if (d < next) next = d; }
        int to = next > now ? (int)((next - now + 999999) / 1000000) : 0;
        struct pollfd pf[2] = {{s, POLLIN, 0}, {tap, POLLIN, 0}};
        poll(pf, 2, to);
        now = now_ns();
        for (int k = 0; k < 512; k++) {
            ssize_t n = recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&qemu, &ql);
            if (n <= 0) break;
            have_qemu = 1;
            if (loss > 0 && (xr() % 1000000) < loss * 1000000) { g2p.dropped++; continue; }
            uint64_t due = now + owd;
            if (rate > 0) { uint64_t st = (uint64_t)(n * 8.0 * 1000.0 / rate); uint64_t base = g2p.last_tx > now ? g2p.last_tx : now; g2p.last_tx = base + st; due = g2p.last_tx + owd; }
            push(&g2p, buf, (int)n, due, qlimit);
        }
        for (int k = 0; k < 512; k++) {
            ssize_t n = read(tap, buf, sizeof buf);
            if (n <= 0) break;
            if (loss > 0 && (xr() % 1000000) < loss * 1000000) { p2g.dropped++; continue; }
            uint64_t due = now + owd;
            if (rate > 0) { uint64_t st = (uint64_t)(n * 8.0 * 1000.0 / rate); uint64_t base = p2g.last_tx > now ? p2g.last_tx : now; if (qlimit && p2g.n >= qlimit) { p2g.dropped++; continue; } p2g.last_tx = base + st; due = p2g.last_tx + owd; }
            push(&p2g, buf, (int)n, due, qlimit);
        }
        now = now_ns();
        while (g2p.n && g2p.q[g2p.head].due <= now) {
            struct pkt *p = &g2p.q[g2p.head];
            if (write(tap, p->d, p->len) < 0 && errno != EAGAIN) { /* ignore */ }
            g2p.head = (g2p.head + 1) % g2p.cap; g2p.n--; g2p.sent++;
        }
        while (p2g.n && p2g.q[p2g.head].due <= now) {
            struct pkt *p = &p2g.q[p2g.head];
            if (have_qemu) sendto(s, p->d, p->len, 0, (struct sockaddr *)&qemu, ql);
            p2g.head = (p2g.head + 1) % p2g.cap; p2g.n--; p2g.sent++;
        }
        if (now - lastlog > 10000000000ull) {
            lastlog = now;
            fprintf(stderr, "bridge: guest->peer sent %llu dropped %llu | peer->guest sent %llu dropped %llu queued %zu\n",
                    (unsigned long long)g2p.sent, (unsigned long long)g2p.dropped, (unsigned long long)p2g.sent, (unsigned long long)p2g.dropped, p2g.n);
        }
    }
}
