import os
import platform
import time
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel


START_TIME = time.time()


app = FastAPI(
    title="Free Cloud Lab",
    description="A browser-developed FastAPI cloud lab running on Render.",
    version="2.0.0",
)

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


class MessageRequest(BaseModel):
    name: str
    message: str


def get_server_info():
    uptime_seconds = int(time.time() - START_TIME)

    return {
        "application": "Free Cloud Lab",
        "version": "2.0.0",
        "python_version": platform.python_version(),
        "operating_system": platform.system(),
        "platform": platform.platform(),
        "processor": platform.processor() or "Not exposed",
        "hostname": platform.node(),
        "uptime_seconds": uptime_seconds,
        "environment": os.getenv("APP_ENV", "development"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "app_name": "Free Cloud Lab",
            "version": "2.0.0",
        },
    )


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "application": "Free Cloud Lab",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/server-info")
async def server_info():
    return get_server_info()


@app.get("/api/hello")
async def hello(name: str = "Cloud User"):
    return {
        "message": f"Hello, {name}!",
        "framework": "FastAPI",
        "hosting": "Render",
        "cost": "₹0",
        "method": "GET",
    }


@app.post("/api/message")
async def post_message(payload: MessageRequest):
    return {
        "success": True,
        "method": "POST",
        "received": {
            "name": payload.name,
            "message": payload.message,
        },
        "reply": f"Hello {payload.name}, your message reached the cloud server.",
    }


@app.get("/api/environment")
async def environment():
    return {
        "app_environment": os.getenv("APP_ENV", "development"),
        "demo_variable": os.getenv(
            "DEMO_MESSAGE",
            "Environment variable not configured yet",
        ),
        "note": "Secrets are intentionally not returned.",
    }


@app.get("/api/external")
async def external_api():
    url = "https://api.github.com"

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "freecloud-demo",
            },
        )

    return {
        "success": response.is_success,
        "status_code": response.status_code,
        "source": "GitHub Public API",
        "response": response.json() if response.is_success else {},
    }