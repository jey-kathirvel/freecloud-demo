import base64
import csv
import hashlib
import io
import ipaddress
import json
import os
import platform
import re
import shlex
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
import qrcode
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

START_TIME = time.time()
APP_VERSION = "3.0.0"
MAX_CURL_CHARS = 65536
MAX_RESPONSE_CHARS = 200000
MAX_REDIRECTS = 5

app = FastAPI(
    title="Free Cloud Dev Tools",
    description="Free browser-based developer toolbox with API, cURL, data, network and utility tools.",
    version=APP_VERSION,
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


class MessageRequest(BaseModel):
    name: str
    message: str


class CurlRequest(BaseModel):
    command: str


class TextRequest(BaseModel):
    text: str


class UrlRequest(BaseModel):
    url: str


class NetworkRequest(BaseModel):
    host: str
    port: int | None = None


class ApiRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str | None = None
    follow_redirects: bool = True


SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "x-api-key", "api-key", "apikey",
    "cookie", "set-cookie", "x-auth-token", "x-access-token",
}


def mask_headers(headers: dict[str, str]) -> dict[str, str]:
    masked = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            masked[key] = "********" if len(value) <= 8 else f"{value[:4]}...{value[-4:]}"
        else:
            masked[key] = value
    return masked


def get_server_info():
    return {
        "application": "Free Cloud Dev Tools",
        "version": APP_VERSION,
        "python_version": platform.python_version(),
        "operating_system": platform.system(),
        "platform": platform.platform(),
        "hostname": platform.node(),
        "uptime_seconds": int(time.time() - START_TIME),
        "environment": os.getenv("APP_ENV", "development"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def normalize_postman_curl(command: str) -> str:
    if not command:
        raise ValueError("cURL command is empty")
    command = command.replace("\ufeff", "").strip()
    if len(command) > MAX_CURL_CHARS:
        raise ValueError(f"cURL command is too large. Maximum is {MAX_CURL_CHARS} characters")
    command = command.replace("\r\n", "\n").replace("\r", "\n")
    command = re.sub(r"\\\s*\n\s*", " ", command)
    command = re.sub(r"\^\s*\n\s*", " ", command)
    command = re.sub(r"`\s*\n\s*", " ", command)
    command = re.sub(r"\s*\n\s*", " ", command)
    command = command.replace("‘", "'").replace("’", "'")
    command = command.replace("“", '"').replace("”", '"')
    return command.strip()


def is_safe_public_host(hostname: str, port: int) -> tuple[bool, str | None]:
    try:
        hostname = hostname.strip().lower().rstrip(".")
        if not hostname or hostname in {"localhost", "localhost.localdomain", "metadata", "metadata.google.internal", "host.docker.internal"}:
            return False, "Localhost and metadata hosts are blocked"
        addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        if not addresses:
            return False, "Hostname could not be resolved"
        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])
            if not ip.is_global:
                return False, f"Non-public address is blocked: {ip}"
        return True, None
    except Exception as exc:
        return False, f"Host validation failed: {exc}"


def is_safe_public_url(url: str) -> tuple[bool, str | None]:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False, "Only http:// and https:// URLs are allowed"
        if not parsed.hostname:
            return False, "URL has no hostname"
        if parsed.username or parsed.password:
            return False, "Credentials embedded in URLs are not allowed"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return is_safe_public_host(parsed.hostname, port)
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
            if i >= len(parts): raise ValueError("Missing value after --request")
            method = parts[i].upper().strip(); explicit_method = True
        elif part in {"-H", "--header"}:
            i += 1
            if i >= len(parts): raise ValueError("Missing value after --header")
            header = parts[i]
            if ":" not in header: raise ValueError(f"Invalid header: {header}")
            key, value = header.split(":", 1); headers[key.strip()] = value.strip()
        elif part.startswith("--header="):
            header = part.split("=", 1)[1]
            if ":" not in header: raise ValueError(f"Invalid header: {header}")
            key, value = header.split(":", 1); headers[key.strip()] = value.strip()
        elif part in {"-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode"}:
            i += 1
            if i >= len(parts): raise ValueError(f"Missing value after {part}")
            value = parts[i]
            if value.startswith("@"):
                raise ValueError("File-based cURL data is not supported")
            body_parts.append(value)
            if not explicit_method and method == "GET": method = "POST"
        elif part.startswith("--data=") or part.startswith("--data-raw="):
            body_parts.append(part.split("=", 1)[1])
            if not explicit_method and method == "GET": method = "POST"
        elif part in {"-L", "--location"}: follow_redirects = True
        elif part in {"-I", "--head"}: method = "HEAD"; explicit_method = True
        elif part == "--url":
            i += 1
            if i >= len(parts): raise ValueError("Missing value after --url")
            url = parts[i]
        elif part.startswith("--url="): url = part.split("=", 1)[1]
        elif part == "--max-time":
            i += 1
            timeout_seconds = min(max(float(parts[i]), 1.0), 30.0)
        elif part in {"-s", "--silent", "-S", "--show-error", "--compressed", "--globoff", "-g", "--fail-with-body", "--fail", "--include", "-i", "-k", "--insecure"}:
            pass
        elif part.startswith("http://") or part.startswith("https://"): url = part
        elif part.startswith("-"):
            raise ValueError(f"Unsupported cURL option: {part}")
        else:
            raise ValueError(f"Unsupported cURL argument: {part}")
        i += 1

    if not url: raise ValueError("No HTTP/HTTPS URL found in the cURL command")
    allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    if method not in allowed_methods: raise ValueError(f"Unsupported HTTP method: {method}")
    return {
        "method": method, "url": url, "headers": headers,
        "body": "&".join(body_parts) if body_parts else None,
        "follow_redirects": follow_redirects, "timeout_seconds": timeout_seconds,
        "normalized": normalized,
    }


async def send_safe_request(parsed: dict) -> tuple[httpx.Response, list[dict]]:
    method, url = parsed["method"], parsed["url"]
    headers, body = dict(parsed.get("headers") or {}), parsed.get("body")
    redirects: list[dict] = []
    timeout_seconds = float(parsed.get("timeout_seconds", 20.0))
    follow_redirects = bool(parsed.get("follow_redirects", True))
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_seconds), follow_redirects=False, verify=True) as client:
        for redirect_number in range(MAX_REDIRECTS + 1):
            safe, reason = is_safe_public_url(url)
            if not safe: raise ValueError(reason or "Unsafe URL blocked")
            response = await client.request(method=method, url=url, headers=headers, content=body)
            if not follow_redirects or response.status_code not in {301, 302, 303, 307, 308}:
                return response, redirects
            location = response.headers.get("location")
            if not location: return response, redirects
            if redirect_number >= MAX_REDIRECTS: raise ValueError("Too many redirects")
            next_url = urljoin(str(response.url), location)
            safe, reason = is_safe_public_url(next_url)
            if not safe: raise ValueError(f"Redirect blocked: {reason}")
            if urlparse(url).hostname != urlparse(next_url).hostname:
                headers = {k: v for k, v in headers.items() if k.lower() not in SENSITIVE_HEADERS}
            redirects.append({"status": response.status_code, "from": str(response.url), "to": next_url})
            if response.status_code == 303 or (response.status_code in {301, 302} and method not in {"GET", "HEAD"}):
                method, body = "GET", None
            url = next_url
    raise ValueError("Request could not be completed")


def response_payload(response: httpx.Response, redirects: list[dict], elapsed_ms: float) -> dict:
    content_type = response.headers.get("content-type", "")
    try:
        body = response.json() if "json" in content_type.lower() else response.text
    except Exception:
        body = response.text
    truncated = False
    if isinstance(body, str) and len(body) > MAX_RESPONSE_CHARS:
        body = body[:MAX_RESPONSE_CHARS]; truncated = True
    return {
        "status": response.status_code, "reason": response.reason_phrase,
        "url": str(response.url), "content_type": content_type,
        "headers": mask_headers(dict(response.headers)), "body": body,
        "elapsed_ms": elapsed_ms, "redirects": redirects, "truncated": truncated,
    }


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"app_name": "Free Cloud Dev Tools", "version": APP_VERSION})


@app.get("/health")
async def health():
    return {"status": "healthy", "application": "Free Cloud Dev Tools", "version": APP_VERSION, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/server-info")
async def server_info(): return get_server_info()


@app.get("/api/hello")
async def hello(name: str = "Cloud User"):
    return {"message": f"Hello, {name}!", "framework": "FastAPI", "hosting": "Render", "cost": "₹0", "method": "GET"}


@app.post("/api/message")
async def post_message(payload: MessageRequest):
    return {"success": True, "method": "POST", "received": payload.model_dump(), "reply": f"Hello {payload.name}, your message reached the cloud server."}


@app.get("/api/environment")
async def environment():
    return {"app_environment": os.getenv("APP_ENV", "development"), "demo_variable": os.getenv("DEMO_MESSAGE", "Environment variable not configured yet"), "note": "Secrets are intentionally not returned."}


@app.post("/api/curl")
async def execute_curl(payload: CurlRequest):
    try:
        parsed = parse_curl(payload.command)
        started = time.perf_counter(); response, redirects = await send_safe_request(parsed)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        return {"success": True, "normalized": parsed["normalized"], "request": {"method": parsed["method"], "url": parsed["url"], "headers": mask_headers(parsed["headers"]), "body": parsed["body"], "follow_redirects": parsed["follow_redirects"]}, "response": response_payload(response, redirects, elapsed_ms)}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@app.post("/api/request")
async def api_request(payload: ApiRequest):
    try:
        method = payload.method.upper().strip()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}: raise ValueError("Unsupported HTTP method")
        parsed = {"method": method, "url": payload.url, "headers": payload.headers, "body": payload.body, "follow_redirects": payload.follow_redirects, "timeout_seconds": 20.0}
        started = time.perf_counter(); response, redirects = await send_safe_request(parsed)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        return {"success": True, "request": {"method": method, "url": payload.url, "headers": mask_headers(payload.headers), "body": payload.body}, "response": response_payload(response, redirects, elapsed_ms)}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@app.post("/api/convert/json-to-yaml")
async def json_to_yaml(payload: TextRequest):
    try:
        data = json.loads(payload.text)
        return {"success": True, "result": yaml.safe_dump(data, sort_keys=False, allow_unicode=True)}
    except Exception as exc: return {"success": False, "error": str(exc)}


@app.post("/api/convert/yaml-to-json")
async def yaml_to_json(payload: TextRequest):
    try:
        data = yaml.safe_load(payload.text)
        return {"success": True, "result": json.dumps(data, indent=2, ensure_ascii=False)}
    except Exception as exc: return {"success": False, "error": str(exc)}


@app.post("/api/convert/csv-to-json")
async def csv_to_json(payload: TextRequest):
    try:
        rows = list(csv.DictReader(io.StringIO(payload.text)))
        return {"success": True, "result": json.dumps(rows, indent=2, ensure_ascii=False)}
    except Exception as exc: return {"success": False, "error": str(exc)}


@app.post("/api/convert/json-to-csv")
async def json_to_csv(payload: TextRequest):
    try:
        data = json.loads(payload.text)
        if isinstance(data, dict): data = [data]
        if not isinstance(data, list) or not data: raise ValueError("JSON must be an object or non-empty array of objects")
        keys = []
        for row in data:
            if not isinstance(row, dict): raise ValueError("Each JSON array item must be an object")
            for key in row:
                if key not in keys: keys.append(key)
        out = io.StringIO(); writer = csv.DictWriter(out, fieldnames=keys); writer.writeheader(); writer.writerows(data)
        return {"success": True, "result": out.getvalue()}
    except Exception as exc: return {"success": False, "error": str(exc)}


@app.post("/api/qr")
async def qr_code(payload: TextRequest):
    try:
        img = qrcode.make(payload.text)
        buf = io.BytesIO(); img.save(buf, format="PNG")
        return {"success": True, "data_uri": "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")}
    except Exception as exc: return {"success": False, "error": str(exc)}


@app.post("/api/network/dns")
async def dns_lookup(payload: NetworkRequest):
    try:
        safe, reason = is_safe_public_host(payload.host, 443)
        if not safe: raise ValueError(reason)
        infos = socket.getaddrinfo(payload.host, None)
        ips = sorted({item[4][0] for item in infos if ipaddress.ip_address(item[4][0]).is_global})
        return {"success": True, "host": payload.host, "addresses": ips}
    except Exception as exc: return {"success": False, "error": str(exc)}


@app.post("/api/network/ssl")
async def ssl_check(payload: NetworkRequest):
    try:
        host = payload.host.strip(); safe, reason = is_safe_public_host(host, 443)
        if not safe: raise ValueError(reason)
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(); cipher = ssock.cipher(); version = ssock.version()
        return {"success": True, "host": host, "subject": dict(x[0] for x in cert.get("subject", [])), "issuer": dict(x[0] for x in cert.get("issuer", [])), "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"), "serial_number": cert.get("serialNumber"), "tls_version": version, "cipher": cipher[0] if cipher else None}
    except Exception as exc: return {"success": False, "error": str(exc)}


@app.post("/api/network/port")
async def port_check(payload: NetworkRequest):
    try:
        port = int(payload.port or 443)
        allowed_ports = {80, 443, 8080, 8443}
        if port not in allowed_ports: raise ValueError("For this public demo, port checking is limited to 80, 443, 8080 and 8443")
        safe, reason = is_safe_public_host(payload.host, port)
        if not safe: raise ValueError(reason)
        started = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.settimeout(3)
        result = sock.connect_ex((payload.host, port)); sock.close()
        return {"success": True, "host": payload.host, "port": port, "open": result == 0, "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}
    except Exception as exc: return {"success": False, "error": str(exc)}
