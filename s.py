import heapq
import hmac
import os
import struct
import time
from functools import total_ordering
from hashlib import blake2s

from iofree import schema
from nacl import bindings
from nacl.public import Box, PrivateKey, PublicKey

_OFFSET = (2 ** 62) + 10

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"


class VerifyError(Exception):
    pass


class HandshakeInitiation(schema.BinarySchema):
    message_type = schema.uint8
    reserved_zero = schema.Bytes(3)
    sender_index = schema.uint32
    unencrypted_ephemeral = schema.Bytes(32)
    encrypted_static = schema.Bytes(48)
    encrypted_timestamp = schema.Bytes(28)
    mac1 = schema.Bytes(16)
    mac2 = schema.Bytes(16)


class HandshakeResponse(schema.BinarySchema):
    message_type = schema.uint8
    reserved_zero = schema.Bytes(3)
    sender_index = schema.uint32
    receiver_index = schema.uint32
    unencrypted_ephemeral = schema.Bytes(48)
    encrypted_nothing = schema.Bytes(16)
    mac1 = schema.Bytes(16)
    mac2 = schema.Bytes(16)


@total_ordering
class PacketData(schema.BinarySchema):
    message_type = schema.uint8
    reserved_zero = schema.Bytes(3)
    receiver_index = schema.uint32
    counter = schema.uint64
    encrypted_encapsulated_packet = schema.Bytes(-1)

    def __gt__(self, other):
        return self.counter > other.counter


class PacketCookieReply(schema.BinarySchema):
    message_type = schema.uint8
    reserved_zero = schema.Bytes(3)
    receiver_index = schema.uint32
    nonce = schema.Bytes(24)
    encrypted_cookie = schema.Bytes(32)

    # @classmethod
    # def make(cls, last_received_msg):
    #     msg = cls(3, b"", initiator.sender_index, os.urandom(24), b"")
    #     cookie = MAC(responder.changing_secret_every_two_minutes, initiator.ip_address)
    #     msg.encrypted_cookie = XAEAD(
    #         HASH(LABEL_COOKIE + responder.static_public),
    #         msg.nonce,
    #         cookie,
    #         last_received_msg.mac1,
    #     )
    #     return msg


message_types = {
    1: HandshakeInitiation,
    2: HandshakeResponse,
    3: PacketCookieReply,
    4: PacketData,
}


def unpack_data(data: bytes):
    message_type = data[0]
    return message_types[message_type].parse(data)


def padding(data: bytes) -> bytes:
    n = len(data) % 16
    if n == 0:
        return data
    return data + b"\x00" * (16 - n)


def unpadding(data: bytes) -> bytes:
    return data.rstrip(b"\x00")


def HASH(input_: bytes) -> bytes:
    return blake2s(input_).digest()


def HMAC(key: bytes, input_: bytes) -> bytes:
    return hmac.digest(key, input_, blake2s)


def MAC(key: bytes, input_: bytes) -> bytes:
    return blake2s(input_, key=key, digest_size=16).digest()


def AEAD(key: bytes, counter: int, plain_text: bytes, auth_text: bytes) -> bytes:
    nonce = b"\x00" * 4 + schema.uint64(counter)
    return bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
        plain_text, auth_text, nonce, key
    )


# from pproxy.cipherpy import *
# class ChaCha20_IETF_POLY1305_Cipher(AEADCipher):
#     KEY_LENGTH = 32
#     IV_LENGTH = 32
#     NONCE_LENGTH = 12
#     TAG_LENGTH = 16
#     def process(self, s, tag=None):
#         nonce = self.nonce
#         if tag is not None:
#             pass
#             #assert tag == poly1305(self.cipher_encrypt, nonce, s)
#         data = self.cipher_encrypt(nonce, s, counter=0)
#         if tag is None:
#             return data, poly1305(self.cipher_encrypt, nonce, data)
#         else:
#             return data
#     encrypt_and_digest = decrypt_and_verify = process
#     def setup(self):
#         self.cipher_encrypt = lambda nonce, s, counter=0: ChaCha20_IETF_Cipher(self.key, setup_key=False, counter=counter).setup_iv(nonce).encrypt(s)


def AEAD_DECRYPT(
    key: bytes, counter: int, cipher_text: bytes, auth_text: bytes
) -> bytes:
    nonce = b"\x00" * 4 + schema.uint64(counter)
    print("decrypt:")
    print("key:", key)
    print("nonce:", nonce)
    print("cipher_text:", cipher_text)
    print("auth_text:", auth_text)
    # cipher_encrypt = lambda nonce, s, counter=0: ChaCha20_IETF_Cipher(key, setup_key=False, counter=counter).setup_iv(nonce).encrypt(s)
    # u = poly1305(cipher_encrypt, nonce, (cipher_text)[16:])
    # print('poly1305', u)
    return bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
        cipher_text, auth_text, nonce, key
    )


def XAEAD(key: bytes, nonce: bytes, plain_text: bytes, auth_text: bytes) -> bytes:
    return bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plain_text, auth_text, nonce, key
    )


def DH_PUBKEY(private_key):
    return bytes(private_key.public_key)


def DH(private_key, public_key):
    return Box(private_key, public_key).shared_key()


def TAI64N():
    seconds, nanoseconds = divmod(time.time_ns(), 1_000_000_000)
    seconds = seconds + _OFFSET
    r = struct.pack(">QI", seconds, nanoseconds)
    # print(r)
    return r


class Peer:
    pass


class Initiator:
    def __init__(
        self,
        static_private: PrivateKey,
        responder_static_public: PublicKey,
        sender_index: int,
        preshared_key: bytes = b"\x00" * 32,
    ):
        self.static_private = static_private
        self.static_public = static_private.public_key
        self.preshared_key = preshared_key
        self.sender_index = sender_index
        self.last_received_cookie = None

        self.responder = Peer()
        self.responder.static_public = responder_static_public

    def build_first_msg(self):
        initiator = self
        responder = self.responder

        initiator.chaining_key = HASH(CONSTRUCTION)
        initiator.hash = HASH(
            HASH(initiator.chaining_key + IDENTIFIER) + bytes(responder.static_public)
        )
        initiator.ephemeral_private = PrivateKey.generate()
        msg = HandshakeInitiation(
            1, b"", initiator.sender_index, b"", b"", b"", b"", b""
        )

        msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        initiator.hash = HASH(initiator.hash + msg.unencrypted_ephemeral)

        temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        initiator.chaining_key = HMAC(temp, b"\x01")

        temp = HMAC(
            initiator.chaining_key,
            DH(initiator.ephemeral_private, responder.static_public),
        )
        initiator.chaining_key = HMAC(temp, b"\x01")
        key = HMAC(temp, initiator.chaining_key + b"\x02")

        msg.encrypted_static = AEAD(
            key, 0, bytes(initiator.static_public), initiator.hash
        )
        initiator.hash = HASH(initiator.hash + msg.encrypted_static)

        temp = HMAC(
            initiator.chaining_key,
            DH(initiator.static_private, responder.static_public),
        )
        initiator.chaining_key = HMAC(temp, b"\x01")
        key = HMAC(temp, initiator.chaining_key + b"\x02")

        msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        initiator.hash = HASH(initiator.hash + msg.encrypted_timestamp)

        msg.mac1 = MAC(
            HASH(LABEL_MAC1 + bytes(responder.static_public)), msg.binary[:-32]
        )
        if initiator.last_received_cookie is not None:
            msg.mac2 = MAC(initiator.last_received_cookie, msg.binary[:-16])
        return msg

    def from_second_msg(self, msg):
        initiator = self
        responder = self.responder

        if initiator.last_received_cookie is not None:
            mac2 = MAC(initiator.last_received_cookie, msg.binary[:-16])
            if msg.mac2 != mac2:
                raise VerifyError("mac2 verify error")
        else:
            if msg.bins["mac2"] != b"\x00" * 16:
                raise VerifyError("mac2 verify error")
        mac1 = MAC(HASH(LABEL_MAC1 + bytes(initiator.static_public)), msg.binary[:-32])
        # print("mac1:", msg.mac1)
        # print("mac1:", mac1)
        if msg.mac1 != mac1:
            raise VerifyError("mac1 verify error")

        responder.sender_index = msg.sender_index
        responder.ephemeral_public = PublicKey(msg.unencrypted_ephemeral)
        initiator.hash = HASH(initiator.hash + msg.unencrypted_ephemeral)

        temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        initiator.chaining_key = HMAC(temp, b"\x01")

        temp = HMAC(
            initiator.chaining_key,
            DH(initiator.ephemeral_private, responder.ephemeral_public),
        )
        initiator.chaining_key = HMAC(temp, b"\x01")

        temp = HMAC(
            initiator.chaining_key,
            DH(initiator.static_private, responder.ephemeral_public),
        )
        initiator.chaining_key = HMAC(temp, b"\x01")

        temp = HMAC(initiator.chaining_key, initiator.preshared_key)
        initiator.chaining_key = HMAC(temp, b"\x01")
        temp2 = HMAC(temp, initiator.chaining_key + b"\x02")
        key = HMAC(temp, temp2 + b"\x03")
        initiator.hash = HASH(initiator.hash + temp2)

        nothing = AEAD_DECRYPT(key, 0, msg.encrypted_nothing, initiator.hash)
        assert nothing == b""
        initiator.hash = HASH(initiator.hash + msg.encrypted_nothing)
        # print("initiator.hash:", initiator.hash)
        # print("initiator.chaining_key:", initiator.chaining_key)
        self._derive()

    def _derive(self):
        initiator = self
        temp1 = HMAC(initiator.chaining_key, b"")
        temp2 = HMAC(temp1, b"\x01")
        temp3 = HMAC(temp1, temp2 + b"\x02")
        initiator.sending_key = temp2
        initiator.receiving_key = temp3
        initiator.sending_key_counter = 0
        initiator.receiving_key_counter = 0

    def build_msg(self, packet):
        initiator = self
        responder = self.responder
        counter = initiator.sending_key_counter
        initiator.sending_key_counter += 1
        encrypted_encapsulated_packet = AEAD(
            initiator.sending_key, counter, padding(packet), b""
        )
        msg = PacketData(
            4, b"", responder.sender_index, counter, encrypted_encapsulated_packet
        )
        return msg

    def decrypt_msg(self, msg):
        initiator = self
        counter = self.receiving_key_counter
        self.receiving_key_counter += 1
        encapsulated_packet = AEAD_DECRYPT(
            initiator.receiving_key, counter, msg.encrypted_encapsulated_packet, b""
        )
        packet = unpadding(encapsulated_packet)
        print("packet:", packet)

    def make_cookie_reply(self):
        responder = self.responder
        nonce = os.urandom(24)
        encrypted_cookie = b""
        msg = PacketCookieReply(3, b"", responder.sender_index, nonce, encrypted_cookie)
        return msg


class Responder:
    def __init__(
        self,
        static_private: PrivateKey,
        sender_index: int,
        preshared_key: bytes = b"\x00" * 32,
    ):
        self.static_private = static_private
        self.static_public = static_private.public_key
        self.last_received_cookie = None
        self.preshared_key = preshared_key
        self.sender_index = sender_index
        self.initiator = Peer()
        self.msg_queue = []

    def build_second_msg(self, msg):
        initiator = self.initiator
        responder = self
        if responder.last_received_cookie is not None:
            mac2 = MAC(responder.last_received_cookie, msg.binary[:-16])
            if msg.mac2 != mac2:
                raise VerifyError("second msg mac2 verify error")
        else:
            if msg.bins["mac2"] != b"\x00" * 16:
                raise VerifyError("second msg mac2 verify error")
        mac1 = MAC(HASH(LABEL_MAC1 + bytes(responder.static_public)), msg.binary[:-32])
        if msg.mac1 != mac1:
            raise VerifyError("second msg mac1 verify error")

        print("unencrypted_ephemeral", msg.unencrypted_ephemeral)
        initiator.sender_index = msg.sender_index
        initiator.ephemeral_public = PublicKey(msg.unencrypted_ephemeral)

        responder.chaining_key = HASH(CONSTRUCTION)
        responder.hash = HASH(
            HASH(responder.chaining_key + IDENTIFIER) + bytes(responder.static_public)
        )
        responder.hash = HASH(responder.hash + msg.unencrypted_ephemeral)

        temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        responder.chaining_key = HMAC(temp, b"\x01")

        temp = HMAC(
            responder.chaining_key,
            DH(responder.static_private, PublicKey(msg.unencrypted_ephemeral)),
        )
        responder.chaining_key = HMAC(temp, b"\x01")
        key = HMAC(temp, responder.chaining_key + b"\x02")
        initiator.static_public = PublicKey(
            AEAD_DECRYPT(key, 0, msg.encrypted_static, responder.hash)
        )
        responder.hash = HASH(responder.hash + msg.encrypted_static)

        temp = HMAC(
            responder.chaining_key,
            DH(responder.static_private, initiator.static_public),
        )
        responder.chaining_key = HMAC(temp, b"\x01")
        key = HMAC(temp, responder.chaining_key + b"\x02")

        responder.decrypted_timestamp = AEAD_DECRYPT(
            key, 0, msg.encrypted_timestamp, responder.hash
        )
        # print(responder.decrypted_timestamp)
        responder.hash = HASH(responder.hash + msg.encrypted_timestamp)

        # build second msg
        responder.ephemeral_private = PrivateKey.generate()
        msg = HandshakeResponse(2, b"", 0, 0, b"", b"", b"", b"")
        msg.sender_index = responder.sender_index
        msg.receiver_index = initiator.sender_index

        msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        responder.hash = HASH(responder.hash + msg.unencrypted_ephemeral)

        temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        responder.chaining_key = HMAC(temp, b"\x01")

        temp = HMAC(
            responder.chaining_key,
            DH(responder.ephemeral_private, initiator.ephemeral_public),
        )
        responder.chaining_key = HMAC(temp, b"\x01")

        temp = HMAC(
            responder.chaining_key,
            DH(responder.ephemeral_private, initiator.static_public),
        )
        responder.chaining_key = HMAC(temp, b"\x01")

        temp = HMAC(responder.chaining_key, responder.preshared_key)
        responder.chaining_key = HMAC(temp, b"\x01")
        temp2 = HMAC(temp, responder.chaining_key + b"\x02")
        key = HMAC(temp, temp2 + b"\x03")
        responder.hash = HASH(responder.hash + temp2)

        msg.encrypted_nothing = AEAD(key, 0, b"", responder.hash)
        responder.hash = HASH(responder.hash + msg.encrypted_nothing)
        # print("responder.hash:", responder.hash)
        # print("responder.chaining_key:", responder.chaining_key)
        self._derive()

        msg.mac1 = MAC(
            HASH(LABEL_MAC1 + bytes(initiator.static_public)), msg.binary[:-32]
        )
        if responder.last_received_cookie is not None:
            msg.mac2 = MAC(responder.last_received_cookie, msg.binary[:-16])
        return msg

    def _derive(self):
        responder = self
        temp1 = HMAC(responder.chaining_key, b"")
        temp2 = HMAC(temp1, b"\x01")
        temp3 = HMAC(temp1, temp2 + b"\x02")
        responder.receiving_key = temp2
        responder.sending_key = temp3
        responder.receiving_key_counter = 0
        responder.sending_key_counter = 0

    def build_msg(self, packet):
        responder = self
        initiator = self.initiator
        counter = responder.sending_key_counter
        responder.sending_key_counter += 1
        encrypted_encapsulated_packet = AEAD(
            responder.sending_key, counter, padding(packet), b""
        )
        msg = PacketData(
            4, b"", initiator.sender_index, counter, encrypted_encapsulated_packet
        )
        return msg

    def decrypt_msg(self, msg):
        responder = self
        counter = self.receiving_key_counter
        self.receiving_key_counter += 1
        encapsulated_packet = AEAD_DECRYPT(
            responder.receiving_key, counter, msg.encrypted_encapsulated_packet, b""
        )
        packet = unpadding(encapsulated_packet)
        return packet

    def receive_msg(self, msg):
        if msg.counter < self.receiving_key_counter:
            return
        elif msg.counter > self.receiving_key_counter:
            heapq.heappush(self.msg_queue, msg)
            return
        try:
            packets = [self.decrypt_msg(msg)]
        except Exception:
            return
        while (
            self.msg_queue and self.msg_queue[0].counter == self.receiving_key_counter
        ):
            msg = heapq.heappop(self.msg_queue)
            try:
                packet = self.decrypt_msg(msg)
            except Exception:
                continue
            packets.append(packet)
        return packets


# sk_initiator = PrivateKey.generate()
# # print(bytes(sk_initiator.public_key))
# sk_responder = PrivateKey.generate()
#
# initiator = Initiator(sk_initiator, sk_responder.public_key, 0)
# msg = initiator.build_first_msg()
# responder = Responder(sk_responder, 20)
# msg = responder.build_second_msg(msg)
# initiator.from_second_msg(msg)
# msg = initiator.build_msg(b"haha")
# packet = responder.decrypt_msg(msg)
# # print(packet)
