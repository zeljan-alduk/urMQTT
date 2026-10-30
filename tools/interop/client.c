/*
 * H2 interop client: one MQTT-over-TLS-1.3 test sequence, built against
 * OpenSSL, wolfSSL or mbedTLS (scripts/interop.sh). Host only, never in
 * the image.
 *
 *   client <port> <ca.pem> <cert.pem> <key.pem> <client id>
 *
 * Prints one line per test: "<test>: ok", "<test>: FAILED <why>" or
 * "<test>: n/a <why>", then "library: <name and version>".
 *
 * Tests: mutual-TLS handshake with CONNECT/CONNACK; resumption with the
 * session ticket; a client KeyUpdate (update_requested) followed by
 * PINGREQ/PINGRESP; CONNECT written one byte per record; one record of
 * nearly 16 KiB (MQTT PUBLISHes and a PINGREQ).
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const char *CA, *CERT, *KEY, *ID;
static int PORT;

__attribute__((unused)) static int tcp(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    struct timeval tv = {10, 0};
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ---- one backend -------------------------------------------------------- */

struct conn;
static struct conn *tls_open(void *session); /* NULL on failure */
static int tls_write(struct conn *c, const unsigned char *b, int n);
static int tls_read(struct conn *c, unsigned char *b, int n); /* <= 0: error */
static int tls_key_update(struct conn *c);                    /* 1 ok, 0 fail, -1 n/a */
static void *tls_session(struct conn *c);                     /* for resumption */
static int tls_resumed(struct conn *c);
static void tls_close(struct conn *c);
static const char *tls_library(void);

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#define LIB(x) wolfSSL_##x
#else
#include <openssl/ssl.h>
#define LIB(x) SSL_##x
#endif

struct conn {
#ifdef USE_WOLFSSL
    WOLFSSL *ssl;
#else
    SSL *ssl;
#endif
    int fd;
};

#ifdef USE_WOLFSSL
static WOLFSSL_CTX *ctx;
#else
static SSL_CTX *ctx;
#endif

static int setup(void) {
#ifdef USE_WOLFSSL
    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) return 0;
    if (wolfSSL_CTX_load_verify_locations(ctx, CA, NULL) != WOLFSSL_SUCCESS) return 0;
    if (wolfSSL_CTX_use_certificate_chain_file(ctx, CERT) != WOLFSSL_SUCCESS) return 0;
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, KEY, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) return 0;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
#else
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return 0;
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    if (SSL_CTX_load_verify_locations(ctx, CA, NULL) != 1) return 0;
    if (SSL_CTX_use_certificate_chain_file(ctx, CERT) != 1) return 0;
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY, SSL_FILETYPE_PEM) != 1) return 0;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
#endif
    return 1;
}

static struct conn *tls_open(void *session) {
    struct conn *c = calloc(1, sizeof *c);
    c->fd = tcp();
    if (c->fd < 0) return free(c), NULL;
    c->ssl = LIB(new)(ctx);
#ifdef USE_WOLFSSL
    wolfSSL_UseSNI(c->ssl, WOLFSSL_SNI_HOST_NAME, "localhost", 9);
    wolfSSL_check_domain_name(c->ssl, "localhost");
#else
    SSL_set_tlsext_host_name(c->ssl, "localhost");
    SSL_set1_host(c->ssl, "localhost");
#endif
    LIB(set_fd)(c->ssl, c->fd);
    if (session) LIB(set_session)(c->ssl, session);
    if (LIB(connect)(c->ssl) != 1) {
        tls_close(c);
        return NULL;
    }
    return c;
}

static int tls_write(struct conn *c, const unsigned char *b, int n) { return LIB(write)(c->ssl, b, n) == n; }
static int tls_read(struct conn *c, unsigned char *b, int n) { return LIB(read)(c->ssl, b, n); }

static int tls_key_update(struct conn *c) {
#ifdef USE_WOLFSSL
    return wolfSSL_update_keys(c->ssl) == WOLFSSL_SUCCESS;
#else
    return SSL_key_update(c->ssl, SSL_KEY_UPDATE_REQUESTED) == 1;
#endif
}

static void *tls_session(struct conn *c) { return LIB(get1_session)(c->ssl); }
static int tls_resumed(struct conn *c) { return LIB(session_reused)(c->ssl) == 1; }

static void tls_close(struct conn *c) {
    LIB(shutdown)(c->ssl);
    LIB(free)(c->ssl);
    close(c->fd);
    free(c);
}

static const char *tls_library(void) {
#ifdef USE_WOLFSSL
    return "wolfSSL " LIBWOLFSSL_VERSION_STRING;
#else
    return OpenSSL_version(OPENSSL_VERSION);
#endif
}

#elif defined(USE_MBEDTLS)
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

struct conn {
    mbedtls_ssl_context ssl;
    mbedtls_net_context net;
    int resumed;
};

static mbedtls_ssl_config conf;
static mbedtls_x509_crt ca, own;
static mbedtls_pk_context pk;

static int setup(void) {
    if (psa_crypto_init() != PSA_SUCCESS) return 0;
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&ca);
    mbedtls_x509_crt_init(&own);
    mbedtls_pk_init(&pk);
    if (mbedtls_x509_crt_parse_file(&ca, CA) != 0) return 0;
    if (mbedtls_x509_crt_parse_file(&own, CERT) != 0) return 0;
    if (mbedtls_pk_parse_keyfile(&pk, KEY, NULL) != 0) return 0;
    if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) return 0;
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);
    if (mbedtls_ssl_conf_own_cert(&conf, &own, &pk) != 0) return 0;
    mbedtls_ssl_conf_session_tickets(&conf, MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
    return 1;
}

static struct conn *tls_open(void *session) {
    struct conn *c = calloc(1, sizeof *c);
    char port[8];
    snprintf(port, sizeof port, "%d", PORT);
    mbedtls_net_init(&c->net);
    mbedtls_ssl_init(&c->ssl);
    if (mbedtls_net_connect(&c->net, "127.0.0.1", port, MBEDTLS_NET_PROTO_TCP) != 0) goto fail;
    if (mbedtls_ssl_setup(&c->ssl, &conf) != 0) goto fail;
    mbedtls_ssl_set_hostname(&c->ssl, "localhost");
    mbedtls_ssl_set_bio(&c->ssl, &c->net, mbedtls_net_send, mbedtls_net_recv, NULL);
    if (session && mbedtls_ssl_set_session(&c->ssl, session) != 0) goto fail;
    int r;
    while ((r = mbedtls_ssl_handshake(&c->ssl)) != 0)
        if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE) goto fail;
    /* mbedTLS has no public "was this resumed" query: the server log
     * decides (scripts/interop.sh). */
    c->resumed = -1;
    return c;
fail:
    tls_close(c);
    return NULL;
}

static int tls_write(struct conn *c, const unsigned char *b, int n) {
    int off = 0;
    while (off < n) {
        int r = mbedtls_ssl_write(&c->ssl, b + off, (size_t)(n - off));
        if (r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (r <= 0) return 0;
        off += r;
    }
    return 1;
}

static int tls_read(struct conn *c, unsigned char *b, int n) {
    for (;;) {
        int r = mbedtls_ssl_read(&c->ssl, b, (size_t)n);
        if (r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET || r == MBEDTLS_ERR_SSL_WANT_READ) continue;
        return r;
    }
}

static int tls_key_update(struct conn *c) {
    (void)c;
    return -1; /* mbedTLS has no TLS 1.3 KeyUpdate API */
}

static void *tls_session(struct conn *c) {
    mbedtls_ssl_session *s = calloc(1, sizeof *s);
    mbedtls_ssl_session_init(s);
    if (mbedtls_ssl_get_session(&c->ssl, s) != 0) return free(s), NULL;
    return s;
}

static int tls_resumed(struct conn *c) { return c->resumed; }

static void tls_close(struct conn *c) {
    mbedtls_ssl_close_notify(&c->ssl);
    mbedtls_ssl_free(&c->ssl);
    mbedtls_net_free(&c->net);
    free(c);
}

static const char *tls_library(void) { return MBEDTLS_VERSION_STRING_FULL; }
#else
#error "build with -DUSE_OPENSSL, -DUSE_WOLFSSL or -DUSE_MBEDTLS"
#endif

/* ---- MQTT and the tests ------------------------------------------------- */

static int connect_packet(unsigned char *out) {
    size_t id = strlen(ID);
    unsigned char *p = out;
    *p++ = 0x10;
    *p++ = (unsigned char)(12 + id);
    memcpy(p, "\x00\x04MQTT\x04\x02\x00\x3c", 10);
    p += 10;
    *p++ = (unsigned char)(id >> 8);
    *p++ = (unsigned char)id;
    memcpy(p, ID, id);
    return (int)(p - out + id);
}

static int read_exact(struct conn *c, unsigned char *b, int n) {
    int got = 0;
    while (got < n) {
        int r = tls_read(c, b + got, n - got);
        if (r <= 0) return 0;
        got += r;
    }
    return 1;
}

static int connack(struct conn *c) {
    unsigned char a[4];
    return read_exact(c, a, 4) && a[0] == 0x20 && a[1] == 2 && a[3] == 0;
}

static int ping(struct conn *c) {
    unsigned char r[2];
    return tls_write(c, (const unsigned char *)"\xc0\x00", 2) && read_exact(c, r, 2) && r[0] == 0xd0 && r[1] == 0;
}

/* Connects and completes CONNECT/CONNACK. */
static struct conn *mqtt(void *session) {
    unsigned char pkt[300];
    struct conn *c = tls_open(session);
    if (!c) return NULL;
    int n = connect_packet(pkt);
    if (!tls_write(c, pkt, n) || !connack(c)) {
        tls_close(c);
        return NULL;
    }
    return c;
}

#define REPORT(name, ok, why) printf("%s: %s\n", name, (ok) ? "ok" : "FAILED " why)

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: %s <port> <ca> <cert> <key> <client id>\n", argv[0]);
        return 2;
    }
    PORT = atoi(argv[1]);
    CA = argv[2];
    CERT = argv[3];
    KEY = argv[4];
    ID = argv[5];
    if (!setup()) {
        printf("setup: FAILED loading certificates\n");
        return 1;
    }

    /* 1. handshake + CONNECT/CONNACK, and a ticket for later. */
    struct conn *c = mqtt(NULL);
    REPORT("handshake", c != NULL, "(mTLS handshake or CONNACK)");
    void *session = NULL;
    if (c) {
        /* The ticket arrives after the handshake; a ping makes sure it is read. */
        ping(c);
        session = tls_session(c);
        tls_close(c);
    }

    /* 2. resumption. */
    if (session) {
        c = mqtt(session);
        if (c && tls_resumed(c) < 0)
            printf("resumption: unknown (the library cannot tell; see the server log)\n");
        else
            REPORT("resumption", c && tls_resumed(c) == 1, "(full handshake instead, or refused)");
        if (c) tls_close(c);
    } else {
        printf("resumption: FAILED no session ticket\n");
    }

    /* 3. KeyUpdate (update_requested), then traffic under the new keys. */
    c = mqtt(NULL);
    if (c) {
        int r = tls_key_update(c);
        if (r < 0) {
            printf("key-update: n/a (no API in this library)\n");
        } else {
            int ok = r == 1 && ping(c) && ping(c);
            REPORT("key-update", ok, "(no PINGRESP under the new keys)");
        }
        tls_close(c);
    } else {
        printf("key-update: FAILED connect\n");
    }

    /* 4. one byte per record: the CONNECT dribbled. */
    c = tls_open(NULL);
    if (c) {
        unsigned char pkt[300];
        int n = connect_packet(pkt), ok = 1;
        for (int i = 0; i < n && ok; i++) ok = tls_write(c, pkt + i, 1);
        ok = ok && connack(c) && ping(c);
        REPORT("records-1-byte", ok, "(CONNECT in 1-byte records)");
        tls_close(c);
    } else {
        printf("records-1-byte: FAILED connect\n");
    }

    /* 5. one record of 16 382 bytes: five PUBLISH (QoS 0) and a PINGREQ. */
    c = mqtt(NULL);
    if (c) {
        static unsigned char big[16384];
        char topic[128];
        int tl = snprintf(topic, sizeof topic, "devices/%s/interop", ID), off = 0;
        int body = 16380 / 5 - 3; /* remaining length per PUBLISH */
        for (int i = 0; i < 5; i++) {
            int payload = body - 2 - tl;
            big[off++] = 0x30;
            big[off++] = (unsigned char)(0x80 | (body & 0x7f));
            big[off++] = (unsigned char)(body >> 7);
            big[off++] = (unsigned char)(tl >> 8);
            big[off++] = (unsigned char)tl;
            memcpy(big + off, topic, (size_t)tl);
            off += tl;
            memset(big + off, 'x', (size_t)payload);
            off += payload;
        }
        big[off++] = 0xc0;
        big[off++] = 0x00;
        unsigned char r[2];
        int ok = tls_write(c, big, off) && read_exact(c, r, 2) && r[0] == 0xd0;
        printf("records-max: %s (%d bytes in one write)\n", ok ? "ok" : "FAILED no PINGRESP", off);
        tls_close(c);
    } else {
        printf("records-max: FAILED connect\n");
    }

    printf("library: %s\n", tls_library());
    return 0;
}
