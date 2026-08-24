from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


app = FastAPI(
    title="FreeCloud Demo",
    description="Sample application running completely in the cloud.",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "app_name": "FreeCloud Demo",
        },
    )


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "application": "FreeCloud Demo",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/hello")
async def hello():
    return {
        "message": "Hello from FreeCloud!",
        "framework": "FastAPI",
        "hosting": "Render Cloud",
        "cost": "₹0",
    }