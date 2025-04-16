# echo-client.py
import sys
import random
import trio

from quicly.client import open_quic_connection
from quicly.connection import SimpleQuicConnection

if sys.version_info < (3, 11):
    pass

# arbitrary, but:
# - must be in between 1024 and 65535
# - can't be in use by some other program on your computer
# - must match what we set in our echo server
PORT = 12345
N_TRANSMISSIONS = 3

async def sender(client_stream, num: int = 0):
    print("sender: started!")
    async with client_stream:
        for pings in range(N_TRANSMISSIONS):
            message = b'test ' + str(pings).encode() + b' from client ' + str(num).encode()
            print(f"sender: sending {message!r}")
            await client_stream.send_all(message)
            await trio.sleep(float(random.randint(0, 10)) / 10.0)


async def receiver(client_stream):
    print("receiver: started!")
    # async for data in client_stream:
    #     print(f"receiver: got data {data!r}")
    for receipt in range(N_TRANSMISSIONS):
        data = await client_stream.receive_some()
        print(f"receiver: got data {data!r}")
    client_stream.close()
    print("receiver: connection closed")
    # raise KeyboardInterrupt


async def parent(num: int = 0):
    host = "127.0.0.1"  # "127.0.0.1" or "0.0.0.0"  # "::1" but never wildcard address "::"

    client_conn = await open_quic_connection(host, PORT)
    print(f'Starting client {num}')

    async with client_conn:
        # async with trio.open_nursery() as nursery:
        #     print(f"parent: spawning sender for client {num} ...")
        #     nursery.start_soon(sender, client_conn, num)
        #     print(f"parent: spawning receiver for client {num}...")
        #     nursery.start_soon(receiver, client_conn)
        for pings in range(N_TRANSMISSIONS):
            message = b'test ' + str(pings).encode() + b' from client ' + str(num).encode()
            print(f"sender: sending {message!r}")
            await client_conn.send_all(message)
            # await trio.sleep(float(random.randint(0, 10)) / 10.0)

            data = await client_conn.receive_some()
            print(f"receiver: got data {data!r}")


async def two_clients():
    async with trio.open_nursery() as nursery:
        # Make two concurrent calls to child()
        nursery.start_soon(parent, 1)
        nursery.start_soon(parent, 2)


try:
    trio.run(parent, )
    # trio.run(two_clients, )
except* KeyboardInterrupt:
    pass
