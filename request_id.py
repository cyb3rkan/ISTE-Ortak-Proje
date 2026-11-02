"""
Inject a stable ``X-Request-ID`` into every request/response.

The middleware honours an inbound ``X-Request-ID`` *only* if it looks safe
(UUID-shaped or short alphanumeric). Anything else is replaced with a freshly
generated UUID4 so attacker-controlled values cannot poison downstream logs.
"""
from __future__ import annotations

import re
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


_SAFE_RID = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")


class RequestIDMiddleware(BaseHTTPMiddleware):
    HEADER_NAME = "X-Request-ID"

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get(self.HEADER_NAME, "")
        if not rid or not _SAFE_RID.fullmatch(rid):
            rid = uuid.uuid4().hex
        request.state.request_id = rid

        response: Response = await call_next(request)
        response.headers[self.HEADER_NAME] = rid
        return response
