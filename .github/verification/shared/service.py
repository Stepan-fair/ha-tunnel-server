import asyncio
import signal
from aiohttp import web


async def listen(app,host,port):
    runner=web.AppRunner(app,access_log=None)
    await runner.setup()
    try:
        await web.TCPSite(runner,host,port).start()
    except BaseException:
        await runner.cleanup()
        raise
    return runner


async def shutdown_event():
    event=asyncio.Event()
    loop=asyncio.get_running_loop()
    for sig in (signal.SIGTERM,signal.SIGINT):
        loop.add_signal_handler(sig,event.set)
    await event.wait()
