import ipaddress
import os
import platform
import re
import shlex
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

START_TIME = time.time()
APP_VERSION = "2.2.0"
MAX_CURL_CHARS = 65536
MAX_RESPONSE_CHARS = 200000
MAX_REDIRECTS = 5

app = FastAPI(
    title="Free Cloud Lab",
    description="Browser-developed FastAPI cloud lab with a safe Postman cURL runner.",
    version=APP_VERSION,
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


class MessageRequest(BaseModel):
    name: str
    message: str


class CurlRequest(BaseModel):
    command: str


SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "cookie",
    "set-cookie",
    "x-auth-token",
    "x-access-token",
}


def get_server_info():
    return {
        "application": "Free Cloud Lab",
        "version": APP_VERSION,
        "python_version": platform.python_version(),
        "operating_system": platform.system(),
        "platform": platform.platform(),
        "processor": platform.processor() or "Not exposed",
        "hostname": platform.node(),
        "uptime_seconds": int(time.time() - START_TIME),
        "environment": os.getenv("APP_ENV", "development"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def mask_headers(headers: dict[str, str]) -> dict[str, str]:
    masked = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            if not value:
                masked[key] = "********"
            elif len(value) <= 8:
                masked[key] = "********"
            else:
                masked[key] = f"{value[:4]}...{value[-4:]}"
        else:
            masked[key] = value
    return masked


def normalize_postman_curl(command: str) -> str:
    """Normalize common Postman/macOS/Linux/Windows copied cURL formatting."""
    if not command:
        raise ValueError("cURL command is empty")

    command = command.replace("\ufeff", "").strip()
    if len(command) > MAX_CURL_CHARS:
        raise ValueError(f"cURL command is too large. Maximum is {MAX_CURL_CHARS} characters")

    # Normalize line endings first.
    command = command.replace("\r\n", "\n").replace("\r", "\n")

    # Postman bash: backslash + newline.
    command = re.sub(r"\\\s*\n\s*", " ", command)
    # Windows cmd: caret + newline.
    command = re.sub(r"\^\s*\n\s*", " ", command)
    # PowerShell: backtick + newline.
    command = re.sub(r"`\s*\n\s*", " ", command)

    # Remaining newlines are safe token separators.
    command = re.sub(r"\s*\n\s*", " ", command)

    # Common smart quotes copied from rich-text sources.
    command = command.replace("‘", "'").replace("’", "'")
    command = command.replace("“", '"').replace("”", '"')

    # Collapse ordinary whitespace outside quoted values is handled by shlex.
    return command.strip()


def is_safe_public_url(url: str) -> tuple[bool, str | None]:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False, "Only http:// and https:// URLs are allowed"
        if not parsed.hostname:
            return False, "URL has no hostname"
        if parsed.username or parsed.password:
            return False, "Credentials embedded in URLs are not allowed"

        hostname = parsed.hostname.lower().rstrip(".")
        blocked_hosts = {
            "localhost",
            "localhost.localdomain",
            "host.docker.internal",
            "metadata.google.internal",
            "metadata",
        }
        if hostname in blocked_hosts:
            return False, "Localhost and metadata hosts are blocked"

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        if not addresses:
            return False, "Hostname could not be resolved"

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])
            if not ip.is_global:
                return False, f"Non-public address is blocked: {ip}"

        return True, None
    except Exception as exc:
        return False, f"URL validation failed: {exc}"


def parse_curl(command: str) -> dict:
    normalized = normalize_postman_curl(command)

    try:
        parts = shlex.split(normalized, posix=True)
    except ValueError as exc:
        raise ValueError(f"Unable to parse cURL quotes: {exc}") from exc

    if not parts or parts[0].lower() not in {"curl", "curl.exe"}:
        raise ValueError("Command must start with curl")

    method = "GET"
    explicit_method = False
    headers: dict[str, str] = {}
    body_parts: list[str] = []
    url = None
    follow_redirects = False
    timeout_seconds = 20.0

    i = 1
    while i < len(parts):
        part = parts[i]

        if part in {"-X", "--request"}:
            i += 1
            if i >= len(parts):
                raise ValueError("Missing value after --request")
            method = parts[i].upper().strip()
            explicit_method = True

        elif part in {"-H", "--header"}:
            i += 1
            if i >= len(parts):
                raise ValueError("Missing value after --header")
            header = parts[i]
            if ":" not in header:
                raise ValueError(f"Invalid header: {header}")
            key, value = header.split(":", 1)
            key = key.strip()
            if not key:
                raise ValueError("Header name cannot be empty")
            headers[key] = value.strip()

        elif part.startswith("--header="):
            header = part.split("=", 1)[1]
            if ":" not in header:
                raise ValueError(f"Invalid header: {header}")
            key, value = header.split(":", 1)
            headers[key.strip()] = value.strip()

        elif part in {
            "-d",
            "--data",
            "--data-raw",
            "--data-binary",
            "--data-ascii",
            "--data-urlencode",
        }:
            i += 1
            if i >= len(parts):
                raise ValueError(f"Missing value after {part}")
            value = parts[i]
            if value.startswith("@") and part == "--data-binary":
                raise ValueError("File uploads using @file are not supported")
            body_parts.append(value)
            if not explicit_method and method == "GET":
                method = "POST"

        elif part.startswith("--data=") or part.startswith("--data-raw="):
            body_parts.append(part.split("=", 1)[1])
            if not explicit_method and method == "GET":
                method = "POST"

        elif part in {"-L", "--location"}:
            follow_redirects = True

        elif part in {"-I", "--head"}:
            method = "HEAD"
            explicit_method = True

        elif part in {"--url"}:
            i += 1
            if i >= len(parts):
                raise ValueError("Missing value after --url")
            url = parts[i]

        elif part.startswith("--url="):
            url = part.split("=", 1)[1]

        elif part in {"--max-time"}:
            i += 1
            if i >= len(parts):
                raise ValueError("Missing value after --max-time")
            try:
                timeout_seconds = min(max(float(parts[i]), 1.0), 30.0)
            except ValueError as exc:
                raise ValueError("--max-time must be numeric") from exc

        elif part in {
            "-s",
            "--silent",
            "-S",
            "--show-error",
            "--compressed",
            "--globoff",
            "-g",
            "--fail-with-body",
            "--fail",
            "--include",
            "-i",
        }:
            pass

        elif part in {"-k", "--insecure"}:
            # Deliberately ignored: TLS verification stays enabled.
            pass

        elif part.startswith("http://") or part.startswith("https://"):
            url = part

        elif part.startswith("-"):
            raise ValueError(
                f"Unsupported cURL option: {part}. "
                "This runner supports common Postman HTTP cURL options."
            )
        else:
            # Postman occasionally exports the URL as a quoted positional token;
            # shlex removes the quotes before we reach this point.
            if part.startswith("http://") or part.startswith("https://"):
                url = part
            else:
                raise ValueError(f"Unsupported cURL argument: {part}")

        i += 1

    if not url:
        raise ValueError("No HTTP/HTTPS URL found in the cURL command")

    allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    if method not in allowed_methods:
        raise ValueError(f"Unsupported HTTP method: {method}")

    body = "&".join(body_parts) if body_parts else None

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "follow_redirects": follow_redirects,
        "timeout_seconds": timeout_seconds,
        "normalized": normalized,
    }


async def send_safe_request(parsed: dict) -> tuple[httpx.Response, list[dict]]:
    method = parsed["method"]
    url = parsed["url"]
    headers = dict(parsed["headers"])
    body = parsed["body"]
    redirects: list[dict] = []

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(parsed["timeout_seconds"]),
        follow_redirects=False,
        verify=True,
    ) as client:
        for redirect_number in range(MAX_REDIRECTS + 1):
            safe, reason = is_safe_public_url(url)
            if not safe:
                raise ValueError(reason or "Unsafe URL blocked")

            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            )

            if not parsed["follow_redirects"] or response.status_code not in {301, 302, 303, 307, 308}:
                return response, redirects

            location = response.headers.get("location")
            if not location:
                return response, redirects

            if redirect_number >= MAX_REDIRECTS:
                raise ValueError(f"Too many redirects. Maximum is {MAX_REDIRECTS}")

            next_url = urljoin(str(response.url), location)
            safe, reason = is_safe_public_url(next_url)
            if not safe:
                raise ValueError(f"Redirect blocked: {reason}")

            current_host = urlparse(url).hostname
            next_host = urlparse(next_url).hostname
            if current_host and next_host and current_host.lower() != next_host.lower():
                for key in list(headers):
                    if key.lower() in SENSITIVE_HEADERS:
                        headers.pop(key, None)

            redirects.append(
                {
                    "status": response.status_code,
                    "from": str(response.url),
                    "to": next_url,
                }
            )

            if response.status_code == 303 or (
                response.status_code in {301, 302} and method not in {"GET", "HEAD"}
            ):
                method = "GET"
                body = None
                headers.pop("Content-Length", None)
                headers.pop("content-length", None)

            url = next_url

    raise ValueError("Request could not be completed")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"app_name": "Free Cloud Lab", "version": APP_VERSION},
    )


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "application": "Free Cloud Lab",
        "version": APP_VERSION,
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
        "received": {"name": payload.name, "message": payload.message},
        "reply": f"Hello {payload.name}, your message reached the cloud server.",
    }


@app.get("/api/environment")
async def environment():
    return {
        "app_environment": os.getenv("APP_ENV", "development"),
        "demo_variable": os.getenv("DEMO_MESSAGE", "Environment variable not configured yet"),
        "note": "Secrets are intentionally not returned.",
    }


@app.get("/api/external")
async def external_api():
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://api.github.com",
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "freecloud-demo",
                },
            )
        return {
            "success": response.is_success,
            "status_code": response.status_code,
            "source": "GitHub Public API",
            "response": response.json() if response.is_success else response.text,
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@app.post("/api/curl")
async def execute_curl(payload: CurlRequest):
    try:
        parsed = parse_curl(payload.command)

        started = time.perf_counter()
        response, redirects = await send_safe_request(parsed)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

        content_type = response.headers.get("content-type", "")
        try:
            response_body = response.json() if "json" in content_type.lower() else response.text
        except Exception:
            response_body = response.text

        truncated = False
        if isinstance(response_body, str) and len(response_body) > MAX_RESPONSE_CHARS:
            response_body = response_body[:MAX_RESPONSE_CHARS]
            truncated = True

        return {
            "success": True,
            "request": {
                "method": parsed["method"],
                "url": parsed["url"],
                "headers": mask_headers(parsed["headers"]),
                "body": parsed["body"],
                "follow_redirects": parsed["follow_redirects"],
            },
            "response": {
                "status": response.status_code,
                "reason": response.reason_phrase,
                "url": str(response.url),
                "content_type": content_type,
                "headers": mask_headers(dict(response.headers)),
                "body": response_body,
                "elapsed_ms": elapsed_ms,
                "redirects": redirects,
                "truncated": truncated,
            },
        }

    except httpx.TimeoutException:
        return {"success": False, "error": "Request timed out"}
    except httpx.ConnectError as exc:
        return {"success": False, "error": f"Unable to connect to remote server: {exc}"}
    except ValueError as exc:
        return {"success": False, "error": str(exc)}
    except Exception as exc:
        return {"success": False, "error": f"Request failed: {exc}"}
