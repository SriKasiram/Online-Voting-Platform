"""
SR-16: a random id for every request, so every audit entry one request writes can be found
together. It is returned in the X-Request-ID header, which lets a polling official quote it.

It is made here and never taken from the client, so nobody can plant one or reuse another
request's. It is written only to the audit log (identity side), never to a ballot-side table
(SR-12): a ballot row with a request id could be matched to that request's audit entries.
"""

import uuid
from collections.abc import Awaitable, Callable
from contextvars import ContextVar

from fastapi import Request, Response

REQUEST_ID_HEADER = "X-Request-ID"

_current: ContextVar[str | None] = ContextVar("request_id", default=None)


def current_request_id() -> str | None:
    """The id of the request being handled, or None outside a request (scripts, start-up)."""
    return _current.get()


async def assign_request_id(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    # SR-16: any X-Request-ID the client sent is ignored: this one replaces it in the response
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    # The endpoint and its dependencies run in a copy of this context, so the audit writer sees it
    token = _current.set(request_id)
    try:
        response = await call_next(request)
    finally:
        _current.reset(token)
    response.headers[REQUEST_ID_HEADER] = request_id
    return response
