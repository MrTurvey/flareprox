#!/usr/bin/env python3
import argparse
import asyncio
import contextlib
import json
import os
import signal
from typing import Optional

from websockets.legacy.server import Serve, WebSocketServerProtocol, serve


class RelayServer:
    def __init__(self, host: str, port: int, password: str, auth_token: Optional[str], handshake_timeout: float) -> None:
        self.host = host
        self.port = port
        self.password = password
        self.auth_token = auth_token or ""
        self.handshake_timeout = handshake_timeout
        self._server: Optional[Serve] = None

    async def start(self) -> None:
        self._server = await serve(
            self._handle_client,
            self.host,
            self.port,
            process_request=self._process_request,
            max_size=None,
        )

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _process_request(self, path, request_headers):
        if self.auth_token:
            header = request_headers.get("Authorization", "")
            if header != self.auth_token:
                body = b"Unauthorized"
                return (401, [("Content-Type", "text/plain"), ("Content-Length", str(len(body)))], body)
        return None

    async def _handle_client(self, websocket: WebSocketServerProtocol, path: str = "") -> None:
        reader = None
        writer: Optional[asyncio.StreamWriter] = None

        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=self.handshake_timeout)
        except Exception:
            await websocket.close(code=4000, reason="Handshake timeout")
            return

        if isinstance(raw, (bytes, bytearray, memoryview)):
            await websocket.close(code=4001, reason="Invalid handshake payload")
            return

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            await websocket.close(code=4002, reason="Invalid handshake JSON")
            return

        if not isinstance(payload, dict):
            await websocket.close(code=4003, reason="Invalid handshake format")
            return

        hostname = payload.get("hostname")
        port = payload.get("port")
        password = payload.get("password")

        if not hostname or not isinstance(hostname, str):
            await websocket.send(json.dumps({"type": "error", "code": "invalid-target", "message": "Missing hostname"}))
            await websocket.close(code=4004, reason="Missing hostname")
            return

        if not isinstance(port, int) or port < 1 or port > 65535:
            await websocket.send(json.dumps({"type": "error", "code": "invalid-target", "message": "Invalid port"}))
            await websocket.close(code=4005, reason="Invalid port")
            return

        if self.password and password != self.password:
            await websocket.send(json.dumps({"type": "error", "code": "auth-failed", "message": "Invalid credentials"}))
            await websocket.close(code=4006, reason="Auth failed")
            return

        try:
            reader, writer = await asyncio.open_connection(hostname, port)
        except Exception as exc:
            await websocket.send(json.dumps({
                "type": "error",
                "code": "connect-failed",
                "message": str(exc) or "Failed to connect upstream"
            }))
            await websocket.close(code=4007, reason="Upstream connect failed")
            return

        await websocket.send(json.dumps({"type": "ready"}))

        async def ws_to_tcp() -> None:
            try:
                async for message in websocket:
                    if isinstance(message, str):
                        writer.write(message.encode("utf-8"))
                    else:
                        writer.write(message)
                    await writer.drain()
            finally:
                if writer is not None:
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()

        async def tcp_to_ws() -> None:
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    await websocket.send(data)
            finally:
                await websocket.close()

        tasks = [asyncio.create_task(ws_to_tcp()), asyncio.create_task(tcp_to_ws())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

        for task in done:
            with contextlib.suppress(Exception):
                task.result()

    async def run_forever(self) -> None:
        await self.start()
        stop_event = asyncio.Event()

        def _stop(*_: object) -> None:
            stop_event.set()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _stop)

        await stop_event.wait()
        await self.close()


async def main() -> None:
    parser = argparse.ArgumentParser(description="FlareProx relay server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8080)), help="Bind port")
    parser.add_argument("--password", default=os.environ.get("FLAREPROX_RELAY_PASSWORD", ""), help="Shared SOCKS password")
    parser.add_argument("--auth-token", default=os.environ.get("FLAREPROX_RELAY_TOKEN", ""), help="Authorization token to expect in the Authorization header")
    parser.add_argument("--handshake-timeout", type=float, default=float(os.environ.get("FLAREPROX_HANDSHAKE_TIMEOUT", "5")), help="Seconds to wait for handshake before closing")

    args = parser.parse_args()

    server = RelayServer(
        host=args.host,
        port=args.port,
        password=args.password,
        auth_token=args.auth_token,
        handshake_timeout=args.handshake_timeout,
    )

    await server.run_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
