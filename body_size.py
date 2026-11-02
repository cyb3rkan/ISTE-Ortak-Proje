"""
Reject oversized request bodies with HTTP 413.

We enforce the limit two ways:

1. Up-front via the ``Content-Length`` header, when present — this rejects
   the request before any body bytes have been read.
2. Streaming receive-wrapper for clients that omit ``Content-Length``: we
   accumulate body bytes and abort as soon as the limit is exceeded.

The middleware is implemented at the raw ASGI level so we can intercept
``receive`` cleanly; ``BaseHTTPMiddleware`` would already have consumed the
body for us.
"""
from __future__ import annotations

import json
from typing import Awaitable, Callable, Optional


_PROBLEM_MEDIA_TYPE = "application/problem+json"


class BodySizeLimitMiddleware:
    def __init__(self, app, max_body_bytes: int) -> None:
        self._app = app
        self._max = int(max_body_bytes)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        cl_raw = headers.get(b"content-length")
        if cl_raw is not None:
            try:
                cl = int(cl_raw)
            except (TypeError, ValueError):
                cl = -1
            if cl > self._max:
                await self._send_413(send)
                return

        received = 0
        max_bytes = self._max
        exceeded = False

        async def _wrapped_receive():
            nonlocal received, exceeded
            message = await receive()
            if exceeded:
                # Drain anything still in the pipe but never forward it.
                return {"type": "http.disconnect"}
            if message.get("type") == "http.request":
                body = message.get("body", b"") or b""
                received += len(body)
                if received > max_bytes:
                    exceeded = True
            return message

        body_too_large_sent = False

        async def _wrapped_send(message):
            nonlocal body_too_large_sent
            if exceeded and not body_too_large_sent:
                body_too_large_sent = True
                await self._send_413(send)
                return
            if exceeded:
                return
            await send(message)

        try:
            await self._app(scope, _wrapped_receive, _wrapped_send)
        finally:
            if exceeded and not body_too_large_sent:
                await self._send_413(send)

    @staticmethod
    async def _send_413(send: Callable[..., Awaitable[None]]) -> None:
        body = json.dumps(
            {
                "type": "https://errors.ioc-enricher.local/payload-too-large",
                "title": "Payload too large",
                "status": 413,
                "detail": "Request body exceeded the configured size limit.",
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", _PROBLEM_MEDIA_TYPE.encode()),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})
