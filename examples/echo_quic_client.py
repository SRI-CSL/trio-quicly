# echo-client.py
import sys
import trio

from trioquic.client import open_quic_connection
from trioquic.connection import SimpleQuicConnection

if sys.version_info < (3, 11):
    pass

# arbitrary, but:
# - must be in between 1024 and 65535
# - can't be in use by some other program on your computer
# - must match what we set in our echo server
PORT = 12345


async def sender(client_stream):
    print("sender: started!")
    for pings in range(3):
        message = b'test ' + str(pings).encode()
        print(f"sender: sending {message!r}")
        await client_stream.send_all(message)
        await trio.sleep(1)
    await client_stream.aclose()

async def receiver(client_stream):
    print("receiver: started!")
    async for data in client_stream:
        print(f"receiver: got data {data!r}")
    print("receiver: connection closed")
    raise KeyboardInterrupt

async def parent():
    host = "127.0.0.1"  # "127.0.0.1"  # "::1"
    print(f"parent: connecting to {host}:{PORT}")
    # TODO: also test with IPv6!
    client_conn = await open_quic_connection(host, PORT)
    async with client_conn:
        async with trio.open_nursery() as nursery:
            print("parent: spawning sender...")
            nursery.start_soon(sender, client_conn)
            print("parent: spawning receiver...")
            nursery.start_soon(receiver, client_conn)

try:
    trio.run(parent, )
except* KeyboardInterrupt:
    pass