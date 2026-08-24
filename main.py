import ipaddress
import os
import platform
import shlex
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel


# ============================================================
# APPLICATION
# ============================================================

START_TIME = time.time()

app = FastAPI(
    title="Free Cloud Lab",
    description=(
        "A browser-developed FastAPI cloud lab "
        "running on Render."
    ),
    version="2.1.0",
)

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static",
)

templates = Jinja2Templates(
    directory="templates"
)


# ============================================================
# REQUEST MODELS
# ============================================================

class MessageRequest(BaseModel):
    name: str
    message: str


class CurlRequest(BaseModel):
    command: str


# ============================================================
# SERVER INFORMATION
# ============================================================

def get_server_info():
    uptime_seconds = int(
        time.time() - START_TIME
    )

    return {
        "application": "Free Cloud Lab",
        "version": "2.1.0",
        "python_version": platform.python_version(),
        "operating_system": platform.system(),
        "platform": platform.platform(),
        "processor": (
            platform.processor()
            or "Not exposed"
        ),
        "hostname": platform.node(),
        "uptime_seconds": uptime_seconds,
        "environment": os.getenv(
            "APP_ENV",
            "development",
        ),
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }


# ============================================================
# HOME PAGE
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse,
)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "app_name": "Free Cloud Lab",
            "version": "2.1.0",
        },
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "application": "Free Cloud Lab",
        "version": "2.1.0",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }


# ============================================================
# SERVER INFO API
# ============================================================

@app.get("/api/server-info")
async def server_info():
    return get_server_info()


# ============================================================
# GET API DEMO
# ============================================================

@app.get("/api/hello")
async def hello(
    name: str = "Cloud User",
):
    return {
        "message": f"Hello, {name}!",
        "framework": "FastAPI",
        "hosting": "Render",
        "cost": "₹0",
        "method": "GET",
    }


# ============================================================
# POST API DEMO
# ============================================================

@app.post("/api/message")
async def post_message(
    payload: MessageRequest,
):
    return {
        "success": True,
        "method": "POST",
        "received": {
            "name": payload.name,
            "message": payload.message,
        },
        "reply": (
            f"Hello {payload.name}, "
            "your message reached "
            "the cloud server."
        ),
    }


# ============================================================
# ENVIRONMENT VARIABLE DEMO
# ============================================================

@app.get("/api/environment")
async def environment():
    return {
        "app_environment": os.getenv(
            "APP_ENV",
            "development",
        ),
        "demo_variable": os.getenv(
            "DEMO_MESSAGE",
            (
                "Environment variable "
                "not configured yet"
            ),
        ),
        "note": (
            "Secrets are intentionally "
            "not returned."
        ),
    }


# ============================================================
# EXTERNAL API DEMO
# ============================================================

@app.get("/api/external")
async def external_api():

    url = "https://api.github.com"

    try:

        async with httpx.AsyncClient(
            timeout=10.0,
        ) as client:

            response = await client.get(
                url,
                headers={
                    "Accept":
                        "application/vnd.github+json",
                    "User-Agent":
                        "freecloud-demo",
                },
            )

        return {
            "success": response.is_success,
            "status_code":
                response.status_code,
            "source":
                "GitHub Public API",
            "response": (
                response.json()
                if response.is_success
                else response.text
            ),
        }

    except Exception as exc:

        return {
            "success": False,
            "error": str(exc),
        }


# ============================================================
# CURL SECURITY
# ============================================================

def is_safe_public_url(
    url: str,
) -> bool:

    try:

        parsed = urlparse(url)

        # Only HTTP / HTTPS
        if parsed.scheme not in {
            "http",
            "https",
        }:
            return False

        hostname = parsed.hostname

        if not hostname:
            return False

        hostname_lower = (
            hostname.lower()
        )

        # Block obvious local targets
        blocked_hosts = {
            "localhost",
            "localhost.localdomain",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "host.docker.internal",
        }

        if hostname_lower in blocked_hosts:
            return False

        # Block cloud metadata targets
        blocked_metadata = {
            "169.254.169.254",
            "metadata.google.internal",
        }

        if hostname_lower in blocked_metadata:
            return False

        # Resolve DNS
        port = (
            parsed.port
            or (
                443
                if parsed.scheme == "https"
                else 80
            )
        )

        addresses = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )

        if not addresses:
            return False

        for address in addresses:

            ip_text = address[4][0]

            ip = ipaddress.ip_address(
                ip_text
            )

            # Reject anything not publicly
            # routable.
            if not ip.is_global:
                return False

        return True

    except Exception:
        return False


# ============================================================
# CURL PARSER
# ============================================================

def parse_curl(
    command: str,
):

    if not command:
        raise ValueError(
            "cURL command is empty"
        )

    # Support copied multiline curl
    command = command.replace(
        "\\\r\n",
        " ",
    )

    command = command.replace(
        "\\\n",
        " ",
    )

    parts = shlex.split(
        command,
        posix=True,
    )

    if not parts:
        raise ValueError(
            "Invalid cURL command"
        )

    if parts[0].lower() != "curl":
        raise ValueError(
            "Command must start with curl"
        )

    method = "GET"

    headers = {}

    body = None

    url = None

    follow_redirects = False

    i = 1

    while i < len(parts):

        part = parts[i]

        # --------------------------------
        # HTTP METHOD
        # --------------------------------

        if part in {
            "-X",
            "--request",
        }:

            i += 1

            if i >= len(parts):
                raise ValueError(
                    "Missing HTTP method"
                )

            method = (
                parts[i]
                .strip()
                .upper()
            )

        # --------------------------------
        # HEADERS
        # --------------------------------

        elif part in {
            "-H",
            "--header",
        }:

            i += 1

            if i >= len(parts):
                raise ValueError(
                    "Missing header value"
                )

            header = parts[i]

            if ":" not in header:
                raise ValueError(
                    f"Invalid header: {header}"
                )

            key, value = (
                header.split(
                    ":",
                    1,
                )
            )

            headers[
                key.strip()
            ] = value.strip()

        # --------------------------------
        # REQUEST BODY
        # --------------------------------

        elif part in {
            "-d",
            "--data",
            "--data-raw",
            "--data-binary",
            "--data-ascii",
        }:

            i += 1

            if i >= len(parts):
                raise ValueError(
                    "Missing request body"
                )

            body = parts[i]

            if method == "GET":
                method = "POST"

        # --------------------------------
        # FOLLOW REDIRECT
        # --------------------------------

        elif part in {
            "-L",
            "--location",
        }:

            follow_redirects = True

        # --------------------------------
        # SAFE OPTIONS WE CAN IGNORE
        # --------------------------------

        elif part in {
            "-s",
            "--silent",
            "-S",
            "--show-error",
            "--compressed",
        }:

            pass

        # --------------------------------
        # URL
        # --------------------------------

        elif (
            part.startswith("http://")
            or
            part.startswith("https://")
        ):

            url = part

        # --------------------------------
        # UNSUPPORTED OPTIONS
        # --------------------------------

        elif part.startswith("-"):

            raise ValueError(
                "Unsupported cURL option: "
                + part
            )

        else:

            # Sometimes URL may not contain
            # scheme when copied from tools.
            # For security we require an
            # explicit HTTP/HTTPS URL.

            raise ValueError(
                "Unsupported cURL argument: "
                + part
            )

        i += 1

    if not url:
        raise ValueError(
            "No HTTP/HTTPS URL found"
        )

    allowed_methods = {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
    }

    if method not in allowed_methods:
        raise ValueError(
            "Unsupported HTTP method: "
            + method
        )

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "follow_redirects":
            follow_redirects,
    }


# ============================================================
# CURL EXECUTION API
# ============================================================

@app.post("/api/curl")
async def execute_curl(
    payload: CurlRequest,
):

    try:

        # --------------------------------
        # Parse curl
        # --------------------------------

        parsed = parse_curl(
            payload.command
        )

        url = parsed["url"]

        # --------------------------------
        # Security validation
        # --------------------------------

        if not is_safe_public_url(
            url
        ):
            return {
                "success": False,
                "error": (
                    "Only public HTTP/HTTPS "
                    "URLs are allowed. "
                    "localhost, private IPs "
                    "and cloud metadata "
                    "addresses are blocked."
                ),
            }

        # --------------------------------
        # Execute HTTP request
        # --------------------------------

        started = (
            time.perf_counter()
        )

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(
                20.0
            ),
            follow_redirects=parsed[
                "follow_redirects"
            ],
        ) as client:

            response = (
                await client.request(
                    method=parsed[
                        "method"
                    ],
                    url=url,
                    headers=parsed[
                        "headers"
                    ],
                    content=parsed[
                        "body"
                    ],
                )
            )

        elapsed_ms = round(
            (
                time.perf_counter()
                - started
            )
            * 1000,
            2,
        )

        # --------------------------------
        # Response content
        # --------------------------------

        content_type = (
            response.headers.get(
                "content-type",
                "",
            )
        )

        if (
            "application/json"
            in content_type.lower()
        ):

            try:
                response_body = (
                    response.json()
                )

            except Exception:
                response_body = (
                    response.text
                )

        else:
            response_body = (
                response.text
            )

        # Prevent huge responses from
        # overwhelming our free server/UI.

        max_response_chars = 100000

        truncated = False

        if isinstance(
            response_body,
            str,
        ):

            if (
                len(response_body)
                > max_response_chars
            ):

                response_body = (
                    response_body[
                        :max_response_chars
                    ]
                )

                truncated = True

        # --------------------------------
        # Return result
        # --------------------------------

        return {
            "success": True,

            "request": {
                "method":
                    parsed["method"],

                "url":
                    parsed["url"],

                "headers":
                    parsed["headers"],

                "body":
                    parsed["body"],
            },

            "response": {
                "status":
                    response.status_code,

                "reason":
                    response.reason_phrase,

                "content_type":
                    content_type,

                "headers":
                    dict(
                        response.headers
                    ),

                "body":
                    response_body,

                "elapsed_ms":
                    elapsed_ms,

                "truncated":
                    truncated,
            },
        }

    except httpx.TimeoutException:

        return {
            "success": False,
            "error": (
                "Request timed out "
                "after 20 seconds."
            ),
        }

    except httpx.ConnectError:

        return {
            "success": False,
            "error": (
                "Unable to connect "
                "to the remote server."
            ),
        }

    except ValueError as exc:

        return {
            "success": False,
            "error": str(exc),
        }

    except Exception as exc:

        return {
            "success": False,
            "error": (
                "Request failed: "
                + str(exc)
            ),
        }