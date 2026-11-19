#!/usr/bin/env python3
"""LXC test fixture: partition one service's DB transport, including live sockets."""
import asyncio
from pathlib import Path
import sys

host, port, local_port, marker = sys.argv[1:]
marker = Path(marker)

async def copy(reader, writer):
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()

async def partition():
    while not marker.exists():
        await asyncio.sleep(0.025)

async def connection(reader, writer):
    upstream = None
    tasks = []
    try:
        if marker.exists():
            return
        peer, upstream = await asyncio.wait_for(asyncio.open_connection(host, int(port)), 2)
        tasks = [asyncio.create_task(copy(reader, upstream)),
                 asyncio.create_task(copy(peer, writer)), asyncio.create_task(partition())]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except (OSError, asyncio.TimeoutError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        if upstream:
            upstream.close()

async def main():
    server = await asyncio.start_server(connection, '127.0.0.1', int(local_port))
    async with server:
        await server.serve_forever()

asyncio.run(main())
