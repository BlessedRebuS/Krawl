"""Dashboard GETs get a statement timeout; everything else stays unlimited."""

import asyncio

from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

from database.core import dashboard_read, limit_dashboard_read
from dependencies import limit_dashboard_reads


class _Connection:
    def __init__(self):
        self.sql = []

    def execute(self, statement):
        self.sql.append(str(statement))


def _app():
    router = APIRouter()

    def _seen():
        conn = _Connection()
        limit_dashboard_read(None, None, conn)
        return conn.sql

    @router.get("/read")
    async def read():
        return await asyncio.to_thread(_seen)

    @router.post("/write")
    async def write():
        return await asyncio.to_thread(_seen)

    app = FastAPI()
    app.include_router(router, dependencies=[Depends(limit_dashboard_reads)])
    return app


def test_only_dashboard_gets_are_limited():
    client = TestClient(_app())
    assert client.get("/read").json() == ["SET LOCAL statement_timeout = '60s'"]
    assert client.post("/write").json() == []
    assert dashboard_read.get() is False  # the caller's context stays unlimited
