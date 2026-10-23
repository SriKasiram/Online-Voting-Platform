"""
SR-05: role-based access control for administrative routes.

ROLE_PERMISSIONS is the only place that says what a role may do. Every route
under /api/admin is declared through AdminRouter, which demands a permission
and attaches require_permission to it, and the API refuses to start if any
/api/admin route was declared some other way. Anything not mapped is denied.
"""

from collections.abc import Callable
from functools import lru_cache
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.routing import APIRoute, iter_route_contexts

from app.deps import CurrentSession, DbSession
from app.audit_events import DENIED
from app.models import Account, AccountRole
from app.security import account_actor, audit

TURNOUT_READ = "turnout:read"
ELECTOR_RESET = "elector:reset"
AUDIT_READ = "audit:read"
AUDIT_VERIFY = "audit:verify"

ROLE_PERMISSIONS: dict[AccountRole, frozenset[str]] = {
    AccountRole.ELECTOR: frozenset(),
    AccountRole.POLLING_OFFICIAL: frozenset({TURNOUT_READ, ELECTOR_RESET}),
    AccountRole.AUDITOR: frozenset({AUDIT_READ, AUDIT_VERIFY, TURNOUT_READ}),
}
ALL_PERMISSIONS = frozenset().union(*ROLE_PERMISSIONS.values())
ADMIN_PREFIX = "/api/admin"

# Endpoint function -> permission, for every route declared through AdminRouter
_ADMIN_ENDPOINTS: dict[Callable[..., Any], str] = {}


@lru_cache
def require_permission(permission: str) -> Callable[..., Account]:
    """
    A dependency that lets the request through only if the signed-in account's
    role has `permission`. No session, a pending session or an expired one gets
    the usual 401 from CurrentSession, which is not audited.
    """

    def check(session: CurrentSession, db: DbSession) -> Account:
        # Read from the database on every request, so a role change applies to the very next one
        account = db.get_one(Account, session.account_id)
        if permission not in ROLE_PERMISSIONS.get(account.role, frozenset()):
            # SR-16: the missing permission is recorded as a fixed reason code (app/audit_events.py)
            actor, role = account_actor(account)
            audit(db, "AUTHZ_DENIED", outcome=DENIED, actor=actor, role=role, reason=permission)
            db.commit()
            raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")
        return account

    check.permission = permission  # type: ignore[attr-defined]
    return check


class AdminRouter(APIRouter):
    """
    An APIRouter whose routes cannot exist without a permission. add_api_route
    requires `permission`, so any other way of adding a route (api_route, put,
    a nested router) fails when the module is imported.
    """

    def add_api_route(self, path: str, endpoint: Callable[..., Any], *, permission: str, **kwargs: Any) -> None:
        if permission not in ALL_PERMISSIONS:
            raise ValueError(f"{path}: {permission!r} is not a permission in ROLE_PERMISSIONS")
        kwargs["dependencies"] = [*(kwargs.get("dependencies") or []), Depends(require_permission(permission))]
        super().add_api_route(path, endpoint, **kwargs)
        _ADMIN_ENDPOINTS[endpoint] = permission

    def get(self, path: str, *, permission: str, **kwargs: Any) -> Callable:  # type: ignore[override]
        return self._route(path, ["GET"], permission, kwargs)

    def post(self, path: str, *, permission: str, **kwargs: Any) -> Callable:  # type: ignore[override]
        return self._route(path, ["POST"], permission, kwargs)

    def _route(self, path: str, methods: list[str], permission: str, kwargs: dict[str, Any]) -> Callable:
        def decorator(endpoint: Callable[..., Any]) -> Callable[..., Any]:
            self.add_api_route(path, endpoint, methods=methods, permission=permission, **kwargs)
            return endpoint

        return decorator


def check_admin_routes(app: FastAPI) -> None:
    """
    Refuses to start the API if any route under /api/admin was not declared
    through AdminRouter with a mapped permission, or lost its permission check.
    Walks included routers too: FastAPI keeps them nested rather than copying
    their routes into app.routes, so iter_route_contexts gives each route's
    full path and every dependency that applies to it.
    """
    for route in iter_route_contexts(app.routes):
        path = route.path or ""
        if path != ADMIN_PREFIX and not path.startswith(ADMIN_PREFIX + "/"):
            continue
        permission = _ADMIN_ENDPOINTS.get(route.endpoint) if isinstance(route.original_route, APIRoute) else None
        checks = {getattr(d.dependency, "permission", None) for d in getattr(route, "dependencies", None) or []}
        if permission not in ALL_PERMISSIONS or permission not in checks:
            raise RuntimeError(f"Refusing to start: {path} is an admin route without a mapped permission")
