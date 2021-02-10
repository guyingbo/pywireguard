import asyncio
import itertools
import base64
from nacl.public import PrivateKey, PublicKey
from s import Initiator, Responder, unpack_data


class WireGuardProtocol(asyncio.DatagramProtocol):
    def __init__(self, static_private, peer_static_public):
        if isinstance(static_private, bytes):
            static_private = PrivateKey(static_private)
        if isinstance(peer_static_public, bytes):
            peer_static_public = PublicKey(peer_static_public)
        self.static_private = static_private
        self.peer_static_public = peer_static_public
        self.initiators = {}
        self.responders = {}
        self.sender_index_generator = itertools.count()

    def connection_made(self, transport) -> None:
        self.transport = transport

    def connection_lost(self, exc) -> None:
        print("lost", exc)

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            print("got:", data)
            msg = unpack_data(data)
            # print(msg)
        except Exception:
            return
        if msg.message_type == 1:
            index = next(self.sender_index_generator)
            responder = Responder(self.static_private, index)
            self.responders[index] = responder
            msg = responder.build_second_msg(msg)
            self.transport.sendto(msg.binary, addr)
        elif msg.message_type == 4:
            index = msg.receiver_index
            packets = self.responders[index].receive_msg(msg)
            if packets is None:
                return
            else:
                print(packets)
        elif msg.message_type == 2:
            index = msg.receiver_index
            initiator = self.initiators[index]
            initiator.from_second_msg(msg)

    def error_received(self, exc: Exception) -> None:
        print("error:", exc)


async def main():
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: WireGuardProtocol(
            base64.b64decode("QMAJwTIrvr5hPBqql9aJ+Y7jqACYr2zyohmS08ovJlI="),
            base64.b64decode("Sqq8FtmJNjvQ7wCS1Rv7kFvR+uwH0kVKQnfA4YQPZV0="),
        ),
        local_addr=("0.0.0.0", 9999),
    )
    await asyncio.sleep(3600)
    # transport.close()


try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
