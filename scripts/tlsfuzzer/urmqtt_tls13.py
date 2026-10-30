#!/usr/bin/env python3
"""H2 conformance probes for urMQTT, built on tlsfuzzer.

The stock tlsfuzzer scripts expect an HTTP server that answers
`GET / HTTP/1.0` and does not require a client certificate, so most of them
cannot run against a broker that requires mutual TLS. These conversations
use the same tlsfuzzer machinery with a client certificate and MQTT as the
application protocol (CONNECT -> CONNACK, PINGREQ -> PINGRESP). They are
modelled on test-tls13-keyupdate, -record-padding, -record-layer-limits,
-zero-length-data, -zero-content-type, -ccs, -0rtt-garbage,
-certificate-verify and -ecdsa-in-certificate-verify.

    PYTHONPATH=<tlsfuzzer>:<tlslite-ng> urmqtt_tls13.py -h HOST -p PORT \\
        -c device.pem -k device.key -i device-001 [probe ...]

Exit status 0 only if every probe ended as expected.
"""
import getopt
import sys
import traceback

from tlsfuzzer.expect import (ExpectAlert, ExpectApplicationData,
                              ExpectCertificate, ExpectCertificateRequest,
                              ExpectCertificateVerify, ExpectChangeCipherSpec,
                              ExpectClose, ExpectEncryptedExtensions,
                              ExpectFinished, ExpectKeyUpdate,
                              ExpectNewSessionTicket, ExpectServerHello)
from tlsfuzzer.helpers import ECDSA_SIG_ALL, RSA_SIG_ALL, key_share_ext_gen
from tlsfuzzer.messages import (AlertGenerator, ApplicationDataGenerator,
                                CertificateGenerator,
                                CertificateVerifyGenerator,
                                ChangeCipherSpecGenerator, ClientHelloGenerator,
                                Connect, FinishedGenerator,
                                KeyUpdateGenerator, RawMessageGenerator,
                                SetMaxRecordSize, SetPaddingCallback,
                                SetRecordVersion,
                                TCPBufferingDisable, TCPBufferingEnable,
                                TCPBufferingFlush, fuzz_encrypted_message,
                                fuzz_message)
from tlsfuzzer.runner import Runner
from tlslite.constants import (AlertDescription, AlertLevel, CipherSuite,
                               ExtensionType, GroupName, KeyUpdateMessageType,
                               PskKeyExchangeMode, SignatureScheme)
from tlslite.extensions import (PskKeyExchangeModesExtension,
                                SignatureAlgorithmsCertExtension,
                                SignatureAlgorithmsExtension,
                                SupportedGroupsExtension,
                                SupportedVersionsExtension, TLSExtension)
from tlslite.utils.cryptomath import getRandomBytes
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain

PINGREQ = bytearray(b"\xc0\x00")
PINGRESP = bytearray(b"\xd0\x00")
CONNACK = bytearray(b"\x20\x02\x00\x00")


def connect_packet(client_id):
    cid = client_id.encode()
    body = b"\x00\x04MQTT\x04\x02\x00\x3c" + len(cid).to_bytes(2, "big") + cid
    return bytearray(bytes([0x10, len(body)]) + body)


class Probes:
    def __init__(self, host, port, cert, key, client_id):
        self.host, self.port = host, port
        self.cert, self.key = cert, key
        self.connect = connect_packet(client_id)

    def hello(self, suite=CipherSuite.TLS_AES_128_GCM_SHA256, extra=None, big=False):
        conv = Connect(self.host, self.port)
        start = conv
        if big:
            # Let tlsfuzzer build records over the limit (its own cap is
            # the legal maximum).
            start = conv.add_child(SetMaxRecordSize(2 ** 16 - 1))
        ext = {
            ExtensionType.key_share: key_share_ext_gen([GroupName.secp256r1]),
            ExtensionType.supported_versions:
                SupportedVersionsExtension().create([(3, 4)]),
            ExtensionType.supported_groups:
                SupportedGroupsExtension().create([GroupName.secp256r1]),
            ExtensionType.signature_algorithms:
                SignatureAlgorithmsExtension().create(
                    [SignatureScheme.ecdsa_secp256r1_sha256]),
            ExtensionType.signature_algorithms_cert:
                SignatureAlgorithmsCertExtension().create(ECDSA_SIG_ALL + RSA_SIG_ALL),
            ExtensionType.psk_key_exchange_modes:
                PskKeyExchangeModesExtension().create([PskKeyExchangeMode.psk_dhe_ke]),
        }
        ext.update(extra or {})
        node = start.add_child(ClientHelloGenerator([suite], extensions=ext))
        return conv, node

    def server_flight(self, node):
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        return node.add_child(ExpectFinished())

    def handshake(self, suite=CipherSuite.TLS_AES_128_GCM_SHA256, big=False):
        """Through our Finished; returns (conversation, last node)."""
        conv, node = self.hello(suite, big=big)
        node = self.server_flight(node)
        node = node.add_child(CertificateGenerator(X509CertChain([self.cert])))
        node = node.add_child(CertificateVerifyGenerator(self.key))
        return conv, node.add_child(FinishedGenerator())

    @staticmethod
    def expect_data(node, data):
        """Server data, after 0..n NewSessionTickets."""
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)
        node.next_sibling = ExpectApplicationData(data)
        return node.next_sibling

    @staticmethod
    def close(node):
        node = node.add_child(AlertGenerator(AlertLevel.warning, AlertDescription.close_notify))
        node = node.add_child(ExpectAlert(AlertLevel.warning, AlertDescription.close_notify))
        node.add_child(ExpectClose())

    @staticmethod
    def fatal(node, desc):
        """The server answers with fatal alert `desc` and closes."""
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)
        node.next_sibling = ExpectAlert(AlertLevel.fatal, desc)
        node.next_sibling.add_child(ExpectClose())

    def mqtt_ok(self, node):
        node = node.add_child(ApplicationDataGenerator(self.connect))
        return self.expect_data(node, CONNACK)

    def build(self):
        P = {}
        for name, suite in [("sanity AES-128-GCM", CipherSuite.TLS_AES_128_GCM_SHA256),
                            ("sanity ChaCha20-Poly1305", CipherSuite.TLS_CHACHA20_POLY1305_SHA256)]:
            conv, node = self.handshake(suite)
            self.close(self.mqtt_ok(node))
            P[name] = conv

        # Client authentication.
        conv, node = self.hello()
        node = self.server_flight(node)
        node = node.add_child(CertificateGenerator())  # empty certificate list
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(AlertLevel.fatal, AlertDescription.certificate_required))
        node.add_child(ExpectClose())
        P["empty client certificate"] = conv

        # A corrupted ECDSA signature (bytes from the end of the message
        # land in the DER signature). Any fatal alert: rustls picks
        # decrypt_error or decode_error depending on whether the DER parses.
        for pos in (-1, -8, -30):
            conv, node = self.hello()
            node = self.server_flight(node)
            node = node.add_child(CertificateGenerator(X509CertChain([self.cert])))
            node = node.add_child(fuzz_message(CertificateVerifyGenerator(self.key), xors={pos: 0x40}))
            node = node.add_child(FinishedGenerator())
            node = node.add_child(ExpectAlert(AlertLevel.fatal))
            node.add_child(ExpectClose())
            P[f"CertificateVerify corrupted at byte {pos}"] = conv

        # KeyUpdate (RFC 8446 §4.6.3).
        conv, node = self.handshake()
        node = self.mqtt_ok(node)
        node = node.add_child(KeyUpdateGenerator(message_type=KeyUpdateMessageType.update_requested))
        node = node.add_child(ApplicationDataGenerator(PINGREQ))
        node = node.add_child(ExpectKeyUpdate(message_type=KeyUpdateMessageType.update_not_requested))
        node = node.add_child(ExpectApplicationData(PINGRESP))
        self.close(node)
        P["KeyUpdate update_requested"] = conv

        conv, node = self.handshake()
        node = self.mqtt_ok(node)
        node = node.add_child(KeyUpdateGenerator(message_type=KeyUpdateMessageType.update_not_requested))
        node = node.add_child(ApplicationDataGenerator(PINGREQ))
        node = node.add_child(ExpectApplicationData(PINGRESP))
        self.close(node)
        P["KeyUpdate update_not_requested"] = conv

        conv, node = self.handshake()
        node = self.mqtt_ok(node)
        for _ in range(3):
            node = node.add_child(KeyUpdateGenerator(message_type=KeyUpdateMessageType.update_not_requested))
        node = node.add_child(ApplicationDataGenerator(PINGREQ))
        node = node.add_child(ExpectApplicationData(PINGRESP))
        self.close(node)
        P["three KeyUpdates in a row"] = conv

        # Record layer (RFC 8446 §5).
        for pad in (1, 100):
            conv, node = self.handshake()
            node = node.add_child(SetPaddingCallback(SetPaddingCallback.fixed_length_cb(pad)))
            self.close(self.mqtt_ok(node))
            P[f"padding of {pad} bytes"] = conv
        conv, node = self.handshake()
        node = node.add_child(SetPaddingCallback(SetPaddingCallback.fill_padding_cb))
        self.close(self.mqtt_ok(node))
        P["padding up to the 2^14 + 1 inner plaintext limit"] = conv

        conv, node = self.handshake()
        for _ in range(3):
            node = node.add_child(ApplicationDataGenerator(bytearray(0)))
        self.close(self.mqtt_ok(node))
        P["zero-length application data before CONNECT"] = conv

        conv, node = self.handshake()
        for b in self.connect:
            node = node.add_child(ApplicationDataGenerator(bytearray([b])))
        self.close(self.expect_data(node, CONNACK))
        P["CONNECT in one-byte records"] = conv

        conv, node = self.handshake()
        node = self.mqtt_ok(node)
        node = node.add_child(ApplicationDataGenerator(PINGREQ * (2 ** 13)))
        # 8192 PINGRESPs come back in some records.
        node = node.add_child(ExpectApplicationData())
        P["2^14 bytes of plaintext in one record"] = conv

        conv, node = self.handshake(big=True)
        node = self.mqtt_ok(node)
        node = node.add_child(ApplicationDataGenerator(bytearray(2 ** 14 + 1)))
        self.fatal(node, AlertDescription.record_overflow)
        P["2^14 + 1 bytes of plaintext"] = conv

        # 2^14 bytes plus padding past the limit: tlsfuzzer will not build
        # it (its padding callback caps at the legal size); the host test
        # `inner_plaintext_over_the_limit_is_record_overflow` covers it.

        for where, xors in [("first byte", {0: 0x01}), ("tag", {-1: 0x01})]:
            conv, node = self.handshake()
            node = self.mqtt_ok(node)
            node = node.add_child(fuzz_encrypted_message(ApplicationDataGenerator(PINGREQ), xors=xors))
            self.fatal(node, AlertDescription.bad_record_mac)
            P[f"record modified in the {where}"] = conv

        conv, node = self.handshake()
        node = self.mqtt_ok(node)
        node = node.add_child(RawMessageGenerator(content_type=0, data=bytearray(0)))
        self.fatal(node, AlertDescription.unexpected_message)
        P["inner content type 0 (no content type)"] = conv

        conv, node = self.handshake()
        node = self.mqtt_ok(node)
        node = node.add_child(RawMessageGenerator(content_type=24, data=bytearray(b"\x01\x00\x10")))
        self.fatal(node, AlertDescription.unexpected_message)
        P["heartbeat content type after the handshake"] = conv

        conv, node = self.handshake()
        node = self.mqtt_ok(node)
        node = node.add_child(RawMessageGenerator(content_type=22, data=bytearray(b"\x01\x00\x00\x00")))
        self.fatal(node, AlertDescription.unexpected_message)
        P["ClientHello after the handshake"] = conv

        conv, node = self.handshake()
        node = self.mqtt_ok(node)
        node = node.add_child(ChangeCipherSpecGenerator(fake=True))
        self.fatal(node, AlertDescription.unexpected_message)
        P["ChangeCipherSpec after the handshake"] = conv

        # 0-RTT stays off: the ClientHello offers early_data (no PSK) and
        # garbage early data follows in the same flight; the server skips
        # it and the handshake completes (RFC 8446 §4.2.10).
        conv = Connect(self.host, self.port)
        node = conv.add_child(TCPBufferingEnable())
        _, hello = self.hello(extra={ExtensionType.early_data: TLSExtension(extType=ExtensionType.early_data)})
        node = node.add_child(hello)
        node = node.add_child(SetRecordVersion((3, 3)))
        node = node.add_child(ApplicationDataGenerator(getRandomBytes(64)))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = self.server_flight(node)
        node = node.add_child(CertificateGenerator(X509CertChain([self.cert])))
        node = node.add_child(CertificateVerifyGenerator(self.key))
        node = node.add_child(FinishedGenerator())
        self.close(self.mqtt_ok(node))
        P["early_data offered without a PSK, garbage early data skipped"] = conv
        return P


def main():
    host, port, cert, key, cid, only = "127.0.0.1", 8883, None, None, "device-001", []
    opts, args = getopt.getopt(sys.argv[1:], "h:p:c:k:i:")
    for o, v in opts:
        if o == "-h":
            host = v
        elif o == "-p":
            port = int(v)
        elif o == "-c":
            cert = X509().parse(open(v).read())
        elif o == "-k":
            key = parsePEMKey(open(v).read(), private=True)
        elif o == "-i":
            cid = v
    only = args
    if cert is None or key is None:
        sys.exit("need -c and -k")
    probes = Probes(host, port, cert, key, cid).build()
    failed, ran = [], 0
    for name, conv in probes.items():
        if only and name not in only:
            continue
        ran += 1
        try:
            Runner(conv).run()
            print(f"ok      {name}", flush=True)
        except Exception:  # noqa: BLE001 - reported per probe
            print(f"FAILED  {name}", flush=True)
            traceback.print_exc(limit=1, file=sys.stdout)
            failed.append(name)
    print(f"\n{ran - len(failed)}/{ran} probes passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
