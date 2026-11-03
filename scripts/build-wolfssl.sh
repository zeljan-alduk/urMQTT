#!/usr/bin/env bash
# Builds the wolfSSL used by the interop matrix (scripts/interop.sh) from a
# pinned, checksummed source release into build/wolfssl.
#
# Why not the distribution package: rustls sends a 32-byte ticket nonce in
# every NewSessionTicket (RFC 8446 allows up to 255). wolfSSL accepts only
# 8 bytes unless it is built with WOLFSSL_TICKET_NONCE_MALLOC, which Ubuntu's
# libwolfssl-dev 5.6.6 is not: the client answered the first ticket with an
# illegal_parameter alert (INVALID_PARAMETER, -425) and every case failed
# after a completed handshake. Homebrew's wolfSSL defines it.
#
#   scripts/build-wolfssl.sh        (needs a C compiler, make, autoconf, automake, libtool)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=5.9.4
SHA256=7256bfc89b183a75183806c7debfa203443873b0b4a562e1b80d68e01b45ac57
PREFIX="$ROOT/build/wolfssl"
if [[ -f "$PREFIX/include/wolfssl/ssl.h" ]] && grep -q "^#define WOLFSSL_TICKET_NONCE_MALLOC" "$PREFIX/include/wolfssl/options.h" \
    && grep -q "LIBWOLFSSL_VERSION_STRING \"$VERSION\"" "$PREFIX/include/wolfssl/version.h"; then
    echo "wolfSSL $VERSION already built in $PREFIX"
    exit 0
fi
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
tarball="$WORK/wolfssl.tar.gz"
curl -fsSL -o "$tarball" "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v$VERSION-stable.tar.gz"
if command -v sha256sum >/dev/null; then sum=$(sha256sum "$tarball" | cut -d' ' -f1); else sum=$(shasum -a 256 "$tarball" | cut -d' ' -f1); fi
[[ $sum == "$SHA256" ]] || { echo "wolfSSL tarball checksum mismatch: $sum" >&2; exit 1; }
mkdir "$WORK/src"
tar xzf "$tarball" -C "$WORK/src" --strip-components=1
cd "$WORK/src"
./autogen.sh >/dev/null 2>&1
./configure --prefix="$PREFIX" --disable-examples --disable-crypttests --enable-tls13 --enable-session-ticket \
    --enable-sni --enable-opensslextra CFLAGS="-O2 -DWOLFSSL_TICKET_NONCE_MALLOC" >/dev/null
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" >/dev/null
make install >/dev/null
echo "wolfSSL $VERSION installed in $PREFIX"
