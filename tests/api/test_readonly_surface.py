"""The public demo has no auth, so the app must expose nothing but reads: every route answers
POST/PUT/PATCH/DELETE with 405, and no route accepts a write, upload, analyze or reset."""

import pytest
from fastapi.testclient import TestClient
from starlette.routing import Mount

from sih26145.api.app import app

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def concrete(path: str) -> str:
    return (path.replace("{alert_id}", "urn:uuid:x").replace("{campaign_id}", "camp-x").replace("{ip}", "10.0.0.1")
            .replace("{path}", "index.html") or "/")


def test_every_route_is_get_only():
    for route in app.routes:
        if isinstance(route, Mount):
            continue  # static files: checked over HTTP below
        methods = set(getattr(route, "methods", None) or ())
        assert methods <= {"GET", "HEAD"}, f"{route.path} allows {methods}"


@pytest.mark.parametrize("method", WRITE_METHODS)
def test_write_methods_get_405_everywhere(method):
    paths = {concrete(r.path) for r in app.routes if not isinstance(r, Mount)}
    if any(isinstance(r, Mount) for r in app.routes):  # the built dashboard is mounted at /
        paths |= {"/", "/index.html", "/assets/x.js"}
    with TestClient(app) as client:
        for path in sorted(paths):
            resp = client.request(method, path)
            assert resp.status_code == 405, f"{method} {path} -> {resp.status_code}"
