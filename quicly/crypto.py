import math
from enum import IntEnum
from typing import *

# from .packet import (
#     QuicProtocolVersion,
#     is_long_header,
# )

class CipherSuite(IntEnum):
    AES_128_GCM_SHA256 = 0x1301
    AES_256_GCM_SHA384 = 0x1302
    CHACHA20_POLY1305_SHA256 = 0x1303
    EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF

CIPHER_SUITES = {
    CipherSuite.AES_128_GCM_SHA256: (b"aes-128-ecb", b"aes-128-gcm"),
    CipherSuite.AES_256_GCM_SHA384: (b"aes-256-ecb", b"aes-256-gcm"),
    CipherSuite.CHACHA20_POLY1305_SHA256: (b"chacha20", b"chacha20-poly1305"),
}
INITIAL_CIPHER_SUITE = CipherSuite.AES_128_GCM_SHA256
INITIAL_SALT_VERSION_1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_SALT_VERSION_2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
SAMPLE_SIZE = 16


def decode_var_length_int(data: bytes, prior_offset: int = 0) -> tuple[int, int]:
    """
    Decode a variable length integer from a stream of bytes.

    See: Appendix A - Sample Variable-Length Integer Decoding

    :param prior_offset: will be added to the number of bytes used to facilitate more compact code when parsing bytes
    :param data: single byte of data to be decoded
    :return: a pair of decoded integer and length of bytes used for decoding (offset into original data)
    """
    # The length of variable-length integers is encoded in the first two bits of the first byte.
    v = data[0]
    prefix = v >> 6
    length = 1 << prefix

    # Once the length is known, remove these bits and read any remaining bytes.
    v = v & 0x3f
    for next_byte in data[1:length]:
        v = (v << 8) + next_byte
    return v, length + prior_offset


def encode_packet_number(full_pn: int, largest_acked: int = None) -> bytes:
    """
    Select an appropriate size for packet number encodings.

    full_pn is the full packet number of the packet being sent.
    largest_acked is the largest packet number that has been acknowledged by the peer in the current packet number
      space, if any.

    See: Appendix A - Sample Packet Number Encoding Algorithm
    """

    # The number of bits must be at least one more than the base-2 logarithm of the number of contiguous unacknowledged
    # packet numbers, including the new packet.
    if largest_acked is None:
        num_unacked = full_pn + 1
    else:
        num_unacked = full_pn - largest_acked

    min_bits = math.log(num_unacked, 2) + 1
    num_bytes = math.ceil(min_bits / 8)

    # Encode the integer value and truncate to the num_bytes least significant bytes.
    total_bytes = (full_pn.bit_length() + 7) // 8 or 1  # Min 1 byte
    encoded_bytes = full_pn.to_bytes(total_bytes, byteorder="big", signed=False)
    # Truncate to the least significant num_bytes
    return encoded_bytes[-num_bytes:]


def decode_packet_number(truncated_pn: int, pn_nbits: int, largest_pn: int) -> int:
    """
    Recover a packet number from a truncated packet number.

    truncated_pn is the value of the Packet Number field.
    pn_nbits is the number of bits in the Packet Number field (8, 16, 24, or 32).
    largest_pn is the largest packet number that has been successfully processed in the current packet number space.

    See: Appendix A - Sample Packet Number Decoding Algorithm
    """
    expected_pn = largest_pn + 1
    pn_win = 1 << pn_nbits
    pn_hwin = pn_win / 2
    pn_mask = pn_win - 1

    # The incoming packet number should be greater than
    # expected_pn - pn_hwin and less than or equal to
    # expected_pn + pn_hwin
    #
    # This means we cannot just strip the trailing bits from
    # expected_pn and add the truncated_pn because that might
    # yield a value outside the window.
    #
    # The following code calculates a candidate value and
    # makes sure it's within the packet number window.
    # Note the extra checks to prevent overflow and underflow.
    candidate_pn = (expected_pn & ~pn_mask) | truncated_pn
    if candidate_pn <= expected_pn - pn_hwin and candidate_pn < (1 << 62) - pn_win:
        return candidate_pn + pn_win
    elif candidate_pn > expected_pn + pn_hwin and candidate_pn >= pn_win:
        return candidate_pn - pn_win
    else:
        return candidate_pn


class HeaderProtection:
    def __init__(self, cipher_name: bytes, key: bytes):
        # TODO: implement
        pass

    def apply(self, plain_header: bytes, protected_payload: bytes) -> bytes:
        # TODO: implement
        return plain_header + protected_payload

    def remove(self, packet: bytes, encrypted_offset: int) -> Tuple[bytes, int]:
        # TODO: implement
        return packet, encrypted_offset


# Callback = Callable[[str], None]
#
#
# def NoCallback(trigger: str) -> None:
#     pass
#
#
# class KeyUnavailableError(CryptoError):
#     pass
#
#
# def derive_key_iv_hp(
#     *, cipher_suite: CipherSuite, secret: bytes, version: int
# ) -> Tuple[bytes, bytes, bytes]:
#     algorithm = cipher_suite_hash(cipher_suite)
#     if cipher_suite in [
#         CipherSuite.AES_256_GCM_SHA384,
#         CipherSuite.CHACHA20_POLY1305_SHA256,
#     ]:
#         key_size = 32
#     else:
#         key_size = 16
#     if version == QuicProtocolVersion.VERSION_2:
#         return (
#             hkdf_expand_label(algorithm, secret, b"quicv2 key", b"", key_size),
#             hkdf_expand_label(algorithm, secret, b"quicv2 iv", b"", 12),
#             hkdf_expand_label(algorithm, secret, b"quicv2 hp", b"", key_size),
#         )
#     else:
#         return (
#             hkdf_expand_label(algorithm, secret, b"quic key", b"", key_size),
#             hkdf_expand_label(algorithm, secret, b"quic iv", b"", 12),
#             hkdf_expand_label(algorithm, secret, b"quic hp", b"", key_size),
#         )
#
#
# class CryptoContext:
#     def __init__(
#         self,
#         key_phase: int = 0,
#         setup_cb: Callback = NoCallback,
#         teardown_cb: Callback = NoCallback,
#     ) -> None:
#         self.aead: Optional[AEAD] = None
#         self.cipher_suite: Optional[CipherSuite] = None
#         self.hp: Optional[HeaderProtection] = None
#         self.key_phase = key_phase
#         self.secret: Optional[bytes] = None
#         self.version: Optional[int] = None
#         self._setup_cb = setup_cb
#         self._teardown_cb = teardown_cb
#
#     def decrypt_packet(
#         self, packet: bytes, encrypted_offset: int, expected_packet_number: int
#     ) -> Tuple[bytes, bytes, int, bool]:
#         if self.aead is None:
#             raise KeyUnavailableError("Decryption key is not available")
#
#         # header protection
#         plain_header, packet_number = self.hp.remove(packet, encrypted_offset)
#         first_byte = plain_header[0]
#
#         # packet number
#         pn_length = (first_byte & 0x03) + 1
#         packet_number = decode_packet_number(
#             packet_number, pn_length * 8, expected_packet_number
#         )
#
#         # detect key phase change
#         crypto = self
#         if not is_long_header(first_byte):
#             key_phase = (first_byte & 4) >> 2
#             if key_phase != self.key_phase:
#                 crypto = next_key_phase(self)
#
#         # payload protection
#         payload = crypto.aead.decrypt(
#             packet[len(plain_header) :], plain_header, packet_number
#         )
#
#         return plain_header, payload, packet_number, crypto != self
#
#     def encrypt_packet(
#         self, plain_header: bytes, plain_payload: bytes, packet_number: int
#     ) -> bytes:
#         assert self.is_valid(), "Encryption key is not available"
#
#         # payload protection
#         protected_payload = self.aead.encrypt(
#             plain_payload, plain_header, packet_number
#         )
#
#         # header protection
#         return self.hp.apply(plain_header, protected_payload)
#
#     def is_valid(self) -> bool:
#         return self.aead is not None
#
#     def setup(self, *, cipher_suite: CipherSuite, secret: bytes, version: int) -> None:
#         hp_cipher_name, aead_cipher_name = CIPHER_SUITES[cipher_suite]
#
#         key, iv, hp = derive_key_iv_hp(
#             cipher_suite=cipher_suite,
#             secret=secret,
#             version=version,
#         )
#         self.aead = AEAD(aead_cipher_name, key, iv)
#         self.cipher_suite = cipher_suite
#         self.hp = HeaderProtection(hp_cipher_name, hp)
#         self.secret = secret
#         self.version = version
#
#         # trigger callback
#         self._setup_cb("tls")
#
#     def teardown(self) -> None:
#         self.aead = None
#         self.cipher_suite = None
#         self.hp = None
#         self.secret = None
#
#         # trigger callback
#         self._teardown_cb("tls")
#
#
# def apply_key_phase(self: CryptoContext, crypto: CryptoContext, trigger: str) -> None:
#     self.aead = crypto.aead
#     self.key_phase = crypto.key_phase
#     self.secret = crypto.secret
#
#     # trigger callback
#     self._setup_cb(trigger)
#
#
# def next_key_phase(self: CryptoContext) -> CryptoContext:
#     algorithm = cipher_suite_hash(self.cipher_suite)
#
#     crypto = CryptoContext(key_phase=int(not self.key_phase))
#     crypto.setup(
#         cipher_suite=self.cipher_suite,
#         secret=hkdf_expand_label(
#             algorithm, self.secret, b"quic ku", b"", algorithm.digest_size
#         ),
#         version=self.version,
#     )
#     return crypto
#
#
# class CryptoPair:
#     def __init__(
#         self,
#         recv_setup_cb: Callback = NoCallback,
#         recv_teardown_cb: Callback = NoCallback,
#         send_setup_cb: Callback = NoCallback,
#         send_teardown_cb: Callback = NoCallback,
#     ) -> None:
#         self.aead_tag_size = 16
#         self.recv = CryptoContext(setup_cb=recv_setup_cb, teardown_cb=recv_teardown_cb)
#         self.send = CryptoContext(setup_cb=send_setup_cb, teardown_cb=send_teardown_cb)
#         self._update_key_requested = False
#
#     def decrypt_packet(
#         self, packet: bytes, encrypted_offset: int, expected_packet_number: int
#     ) -> Tuple[bytes, bytes, int]:
#         plain_header, payload, packet_number, update_key = self.recv.decrypt_packet(
#             packet, encrypted_offset, expected_packet_number
#         )
#         if update_key:
#             self._update_key("remote_update")
#         return plain_header, payload, packet_number
#
#     def encrypt_packet(
#         self, plain_header: bytes, plain_payload: bytes, packet_number: int
#     ) -> bytes:
#         if self._update_key_requested:
#             self._update_key("local_update")
#         return self.send.encrypt_packet(plain_header, plain_payload, packet_number)
#
#     def setup_initial(self, cid: bytes, is_client: bool, version: int) -> None:
#         if is_client:
#             recv_label, send_label = b"server in", b"client in"
#         else:
#             recv_label, send_label = b"client in", b"server in"
#
#         if version == QuicProtocolVersion.VERSION_2:
#             initial_salt = INITIAL_SALT_VERSION_2
#         else:
#             initial_salt = INITIAL_SALT_VERSION_1
#
#         algorithm = cipher_suite_hash(INITIAL_CIPHER_SUITE)
#         initial_secret = hkdf_extract(algorithm, initial_salt, cid)
#         self.recv.setup(
#             cipher_suite=INITIAL_CIPHER_SUITE,
#             secret=hkdf_expand_label(
#                 algorithm, initial_secret, recv_label, b"", algorithm.digest_size
#             ),
#             version=version,
#         )
#         self.send.setup(
#             cipher_suite=INITIAL_CIPHER_SUITE,
#             secret=hkdf_expand_label(
#                 algorithm, initial_secret, send_label, b"", algorithm.digest_size
#             ),
#             version=version,
#         )
#
#     def teardown(self) -> None:
#         self.recv.teardown()
#         self.send.teardown()
#
#     def update_key(self) -> None:
#         self._update_key_requested = True
#
#     @property
#     def key_phase(self) -> int:
#         if self._update_key_requested:
#             return int(not self.recv.key_phase)
#         else:
#             return self.recv.key_phase
#
#     def _update_key(self, trigger: str) -> None:
#         apply_key_phase(self.recv, next_key_phase(self.recv), trigger=trigger)
#         apply_key_phase(self.send, next_key_phase(self.send), trigger=trigger)
#         self._update_key_requested = False
