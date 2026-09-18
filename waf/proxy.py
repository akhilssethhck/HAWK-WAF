from flask import (
    Flask,
    request,
    Response,
    jsonify
)

import requests
import time
import secrets
import os
from pathlib import Path

from urllib.parse import (
    urlencode,
    urlparse,
    unquote_plus
)

from waf.config import HAWKConfig
from waf.detector import WAFDetector
from waf.logger import log_event
from waf.rate_limit import RateLimiter
from waf.challenge import HAWKChallenge
from waf.bot_detector import HAWKBotDetector
from waf.website_registry import WebsiteRegistry


# ============================================================
# HAWK WAF
# Web Application Firewall + Bot Protection
# ============================================================

app = Flask(__name__)


# ============================================================
# REQUEST ID RESPONSE HEADER
# ============================================================

@app.after_request
def add_request_id_header(response):

    request_id = request.environ.get(
        "hawk_request_id"
    )

    if request_id:
        response.headers["X-Request-ID"] = request_id

    return response


# ============================================================
# LOAD CONFIGURATION
# ============================================================

config = HAWKConfig()

website_registry = WebsiteRegistry(config)

# ============================================================
# RUNTIME CONFIGURATION RELOAD
# ============================================================

_CONFIG_FILE = Path("config.json")
_CONFIG_MTIME = None


def reload_runtime_config():
    global config
    global _CONFIG_MTIME
    global RATE_LIMIT_ENABLED
    global RATE_LIMIT_MAX
    global RATE_LIMIT_WINDOW
    global CHALLENGE_ENABLED
    global CHALLENGE_MODE
    global CHALLENGE_TOKEN_LIFETIME
    global BOT_PROTECTION_ENABLED
    global BOT_MODE
    global BOT_REQUEST_WINDOW
    global BOT_MAX_REQUESTS
    global MAX_BODY_SIZE
    global ALLOWED_METHODS
    global UPSTREAM_TIMEOUT
    global BACKEND_HOST
    global BACKEND_PORT
    global BACKEND_URL
    global website_registry

    try:
        mtime = _CONFIG_FILE.stat().st_mtime

        if _CONFIG_MTIME == mtime:
            return

        config = HAWKConfig()

        website_registry = WebsiteRegistry(config)

        BACKEND_HOST = config.get(
            "backend",
            "host",
            "127.0.0.1"
        )

        BACKEND_PORT = config.get(
            "backend",
            "port",
            5001
        )

        BACKEND_URL = (
            f"http://{BACKEND_HOST}:{BACKEND_PORT}"
        )

        RATE_LIMIT_ENABLED = config.get(
            "rate_limit",
            "enabled",
            True
        )

        RATE_LIMIT_MAX = config.get(
            "rate_limit",
            "max_requests",
            20
        )

        RATE_LIMIT_WINDOW = config.get(
            "rate_limit",
            "window_seconds",
            10
        )

        CHALLENGE_ENABLED = config.get(
            "challenge",
            "enabled",
            True
        )

        CHALLENGE_MODE = config.get(
            "challenge",
            "mode",
            "suspicious"
        )

        CHALLENGE_TOKEN_LIFETIME = config.get(
            "challenge",
            "token_lifetime",
            300
        )

        BOT_PROTECTION_ENABLED = config.get(
            "bot_protection",
            "enabled",
            True
        )

        BOT_MODE = config.get(
            "bot_protection",
            "mode",
            "challenge"
        )

        BOT_REQUEST_WINDOW = config.get(
            "bot_protection",
            "request_window",
            10
        )

        BOT_MAX_REQUESTS = config.get(
            "bot_protection",
            "max_requests",
            30
        )

        # ----------------------------------------------------
        # REQUEST SECURITY
        # ----------------------------------------------------

        MAX_BODY_SIZE = config.get(
            "request_security",
            "max_body_size",
            1048576
        )

        try:
            MAX_BODY_SIZE = max(
                1024,
                int(MAX_BODY_SIZE)
            )
        except (TypeError, ValueError):
            MAX_BODY_SIZE = 1048576

        ALLOWED_METHODS = config.get(
            "request_security",
            "allowed_methods",
            [
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
                "HEAD"
            ]
        )

        if not isinstance(
            ALLOWED_METHODS,
            list
        ):
            ALLOWED_METHODS = [
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
                "HEAD"
            ]

        ALLOWED_METHODS = {
            str(method).upper()
            for method in ALLOWED_METHODS
        }

        UPSTREAM_TIMEOUT = config.get(
            "request_security",
            "upstream_timeout",
            10
        )

        try:
            UPSTREAM_TIMEOUT = max(
                1,
                int(UPSTREAM_TIMEOUT)
            )
        except (TypeError, ValueError):
            UPSTREAM_TIMEOUT = 10

        _CONFIG_MTIME = mtime

        print("[CONFIG] Runtime configuration reloaded")

    except Exception as error:
        print(f"[CONFIG] Reload failed: {error}")


# ============================================================
# WAF CONFIGURATION
# ============================================================

WAF_HOST = config.get(
    "waf",
    "host",
    "127.0.0.1"
)

WAF_PORT = config.get(
    "waf",
    "port",
    8080
)


# ============================================================
# BACKEND CONFIGURATION
# ============================================================

BACKEND_HOST = config.get(
    "backend",
    "host",
    "127.0.0.1"
)

BACKEND_PORT = config.get(
    "backend",
    "port",
    5001
)


BACKEND_URL = (
    f"http://{BACKEND_HOST}:{BACKEND_PORT}"
)


# ============================================================
# RATE LIMIT CONFIGURATION
# ============================================================

RATE_LIMIT_ENABLED = config.get(
    "rate_limit",
    "enabled",
    True
)

RATE_LIMIT_MAX = config.get(
    "rate_limit",
    "max_requests",
    20
)

RATE_LIMIT_WINDOW = config.get(
    "rate_limit",
    "window_seconds",
    10
)


# ============================================================
# CHALLENGE CONFIGURATION
# ============================================================

CHALLENGE_ENABLED = config.get(
    "challenge",
    "enabled",
    True
)

CHALLENGE_MODE = config.get(
    "challenge",
    "mode",
    "suspicious"
)

CHALLENGE_TOKEN_LIFETIME = config.get(
    "challenge",
    "token_lifetime",
    300
)


# ============================================================
# BOT PROTECTION CONFIGURATION
# ============================================================

BOT_PROTECTION_ENABLED = config.get(
    "bot_protection",
    "enabled",
    True
)

BOT_MODE = config.get(
    "bot_protection",
    "mode",
    "challenge"
)

BOT_REQUEST_WINDOW = config.get(
    "bot_protection",
    "request_window",
    10
)

BOT_MAX_REQUESTS = config.get(
    "bot_protection",
    "max_requests",
    30
)


# ============================================================
# REQUEST SECURITY CONFIGURATION
# ============================================================

MAX_BODY_SIZE = config.get(
    "request_security",
    "max_body_size",
    1048576
)

try:
    MAX_BODY_SIZE = max(
        1024,
        int(MAX_BODY_SIZE)
    )
except (TypeError, ValueError):
    MAX_BODY_SIZE = 1048576


ALLOWED_METHODS = config.get(
    "request_security",
    "allowed_methods",
    [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD"
    ]
)

if not isinstance(
    ALLOWED_METHODS,
    list
):
    ALLOWED_METHODS = [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD"
    ]

ALLOWED_METHODS = {
    str(method).upper()
    for method in ALLOWED_METHODS
}


UPSTREAM_TIMEOUT = config.get(
    "request_security",
    "upstream_timeout",
    10
)

try:
    UPSTREAM_TIMEOUT = max(
        1,
        int(UPSTREAM_TIMEOUT)
    )
except (TypeError, ValueError):
    UPSTREAM_TIMEOUT = 10


# ============================================================
# CHALLENGE SECRET
# ============================================================

CHALLENGE_SECRET = os.environ.get(
    "HAWK_CHALLENGE_SECRET",
    ""
).strip()


if not CHALLENGE_SECRET:

    raise RuntimeError(
        "HAWK_CHALLENGE_SECRET environment variable is required."
    )


# ============================================================
# INITIALIZE COMPONENTS
# ============================================================

detector = WAFDetector(
    "rules/rules.json"
)


rate_limiter = RateLimiter(
    max_requests=RATE_LIMIT_MAX,
    window_seconds=RATE_LIMIT_WINDOW
)


challenge = HAWKChallenge(
    secret=CHALLENGE_SECRET,
    token_lifetime=CHALLENGE_TOKEN_LIFETIME
)


bot_detector = HAWKBotDetector(
    request_window=BOT_REQUEST_WINDOW,
    max_requests=BOT_MAX_REQUESTS
)


# ============================================================
# SECURITY HEADERS
# ============================================================

def add_security_headers(response):

    security_policy = request.environ.get(
        "hawk_security_headers",
        {}
    )

    if not isinstance(
        security_policy,
        dict
    ):
        security_policy = {}

    enabled = bool(
        security_policy.get(
            "enabled",
            True
        )
    )

    if not enabled:
        return response

    x_content_type_options = str(
        security_policy.get(
            "x_content_type_options",
            "nosniff"
        )
    ).strip()

    x_frame_options = str(
        security_policy.get(
            "x_frame_options",
            "DENY"
        )
    ).strip()

    referrer_policy = str(
        security_policy.get(
            "referrer_policy",
            "strict-origin-when-cross-origin"
        )
    ).strip()

    permissions_policy = str(
        security_policy.get(
            "permissions_policy",
            "camera=(), microphone=(), geolocation=()"
        )
    ).strip()

    strict_transport_security = str(
        security_policy.get(
            "strict_transport_security",
            ""
        )
    ).strip()

    if x_content_type_options:
        response.headers[
            "X-Content-Type-Options"
        ] = x_content_type_options

    if x_frame_options:
        response.headers[
            "X-Frame-Options"
        ] = x_frame_options

    if referrer_policy:
        response.headers[
            "Referrer-Policy"
        ] = referrer_policy

    if permissions_policy:
        response.headers[
            "Permissions-Policy"
        ] = permissions_policy

    # Only send HSTS when explicitly configured.
    if strict_transport_security:
        response.headers[
            "Strict-Transport-Security"
        ] = strict_transport_security

    return response


# ============================================================
# SAFE REDIRECT
# ============================================================

def get_safe_redirect(value):

    if not value:

        return "/"


    value = str(value)


    parsed = urlparse(
        value
    )


    # Reject absolute URLs

    if parsed.scheme:

        return "/"


    # Reject hostnames

    if parsed.netloc:

        return "/"


    # Reject protocol-relative URLs

    if value.startswith(
        "//"
    ):

        return "/"


    # Only allow relative paths

    if not value.startswith(
        "/"
    ):

        return "/"


    return value


# ============================================================
# CHALLENGE URL
# ============================================================

def build_challenge_url():

    redirect_url = request.full_path


    if redirect_url.endswith(
        "?"
    ):

        redirect_url = (
            redirect_url[:-1]
        )


    redirect_url = get_safe_redirect(
        redirect_url
    )


    return (
        "/__hawk_challenge?"
        + urlencode(
            {
                "redirect":
                    redirect_url
            }
        )
    )


# ============================================================
# CHALLENGE PAGE
# ============================================================

@app.route(
    "/__hawk_challenge",
    methods=["GET"]
)

def hawk_challenge():

    redirect_url = request.args.get(
        "redirect",
        "/"
    )


    redirect_url = get_safe_redirect(
        redirect_url
    )


    challenge_data = (
        challenge.create_challenge(
            redirect=redirect_url
        )
    )


    challenge_token = (
        challenge.create_token(
            challenge_data
        )
    )


    script_nonce = (
        secrets.token_urlsafe(16)
    )


    html = f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>HAWK WAF Security Verification</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{

    margin: 0;

    min-height: 100vh;

    display: flex;

    align-items: center;

    justify-content: center;

    background:
        linear-gradient(
            135deg,
            #080808,
            #160606
        );

    color: white;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

}}

.container {{

    width: 90%;

    max-width: 520px;

    padding: 40px;

    border:
        1px solid #5c1111;

    border-radius: 14px;

    background: #100909;

    box-shadow:
        0 0 40px
        rgba(150, 0, 0, 0.25);

    text-align: center;

}}

.logo {{

    font-size: 42px;

    font-weight: bold;

    letter-spacing: 4px;

    color: #ff3333;

    margin-bottom: 10px;

}}

.subtitle {{

    color: #aaa;

    margin-bottom: 30px;

}}

.loader {{

    width: 46px;

    height: 46px;

    margin:
        0 auto 25px;

    border-radius: 50%;

    border:
        4px solid #321111;

    border-top:
        4px solid #ff3333;

    animation:
        spin 1s linear infinite;

}}

@keyframes spin {{

    from {{
        transform: rotate(0deg);
    }}

    to {{
        transform: rotate(360deg);
    }}

}}

.status {{

    font-size: 16px;

    color: #ddd;

}}

.small {{

    margin-top: 25px;

    color: #777;

    font-size: 12px;

}}

</style>

</head>

<body>

<div class="container">

    <div class="logo">
        HAWK
    </div>

    <div class="subtitle">
        Web Application Firewall
    </div>

    <div class="loader"></div>

    <div
        id="status"
        class="status"
    >
        Verifying your browser...
    </div>

    <div class="small">
        HAWK Security Verification
    </div>

</div>


<script nonce="{script_nonce}">

async function generateProof() {{

    try {{

        const data = {{

            userAgentLength:
                navigator.userAgent.length,

            screenWidth:
                screen.width,

            screenHeight:
                screen.height,

            colorDepth:
                screen.colorDepth,

            language:
                navigator.language || "",

            timezone:
                Intl.DateTimeFormat()
                .resolvedOptions()
                .timeZone || ""

        }};


        const raw =
            JSON.stringify(data);


        const encoder =
            new TextEncoder();


        const bytes =
            encoder.encode(raw);


        const hash =
            await crypto.subtle.digest(
                "SHA-256",
                bytes
            );


        const hashArray =
            Array.from(
                new Uint8Array(hash)
            );


        const proof =
            hashArray
                .map(
                    b =>
                        b.toString(16)
                        .padStart(2, "0")
                )
                .join("");


        return proof;


    }} catch (error) {{

        console.error(error);

        return null;

    }}

}}


async function verifyBrowser() {{

    const status =
        document.getElementById(
            "status"
        );


    const proof =
        await generateProof();


    if (!proof) {{

        status.textContent =
            "Browser verification failed.";

        return;

    }}


    try {{

        const response =
            await fetch(
                "/__hawk_verify",
                {{

                    method: "POST",

                    headers: {{

                        "Content-Type":
                            "application/json"

                    }},

                    body:
                        JSON.stringify({{

                            proof: proof,

                            challenge:
                                "{challenge_token}"

                        }})

                }}
            );


        const result =
            await response.json();


        if (
            response.ok &&
            result.success
        ) {{

            status.textContent =
                "Verification successful. Redirecting...";


            setTimeout(
                function() {{

                    window.location.href =
                        result.redirect || "/";

                }},
                400
            );


        }} else {{

            status.textContent =
                "Verification failed.";

        }}


    }} catch (error) {{

        console.error(error);

        status.textContent =
            "Verification service unavailable.";

    }}

}}


verifyBrowser();

</script>

</body>

</html>
"""


    response = Response(
        html,
        status=200,
        mimetype="text/html"
    )


    response.headers[
        "Content-Security-Policy"
    ] = (
        "default-src 'self'; "
        f"script-src 'self' "
        f"'nonce-{script_nonce}'; "
        "style-src 'self' 'unsafe-inline'"
    )


    return add_security_headers(
        response
    )


# ============================================================
# CHALLENGE VERIFICATION
# ============================================================

@app.route(
    "/__hawk_verify",
    methods=["POST"]
)

def hawk_verify():

    try:

        data = request.get_json(
            silent=True
        )


        if not data:

            response = jsonify(
                {
                    "success": False,
                    "error":
                        "Invalid request"
                }
            )

            return (
                add_security_headers(
                    response
                ),
                400
            )


        proof = data.get(
            "proof",
            ""
        )


        challenge_token = data.get(
            "challenge",
            ""
        )


        # ----------------------------------------------------
        # Validate proof
        # ----------------------------------------------------

        if not isinstance(
            proof,
            str
        ):

            response = jsonify(
                {
                    "success": False,
                    "error":
                        "Invalid proof"
                }
            )

            return (
                add_security_headers(
                    response
                ),
                400
            )


        if len(proof) != 64:

            response = jsonify(
                {
                    "success": False,
                    "error":
                        "Invalid proof length"
                }
            )

            return (
                add_security_headers(
                    response
                ),
                400
            )


        if not all(
            character in
            "0123456789abcdef"
            for character
            in proof.lower()
        ):

            response = jsonify(
                {
                    "success": False,
                    "error":
                        "Invalid proof format"
                }
            )

            return (
                add_security_headers(
                    response
                ),
                400
            )


        # ----------------------------------------------------
        # Verify challenge
        # ----------------------------------------------------

        verified_challenge = (
            challenge.verify_token(
                challenge_token
            )
        )


        if not verified_challenge:

            response = jsonify(
                {
                    "success": False,
                    "error":
                        "Challenge expired or invalid"
                }
            )

            return (
                add_security_headers(
                    response
                ),
                403
            )


        redirect_url = get_safe_redirect(
            verified_challenge.get(
                "redirect",
                "/"
            )
        )


        access_token = (
            challenge.create_token(
                verified_challenge
            )
        )


        response = jsonify(
            {
                "success": True,
                "redirect":
                    redirect_url
            }
        )


        response.set_cookie(

            "HAWK_CHALLENGE",

            access_token,

            max_age=
                CHALLENGE_TOKEN_LIFETIME,

            httponly=True,

            # False because this lab uses HTTP.
            # Set True when deployed behind HTTPS.

            secure=False,

            samesite="Lax",

            path="/"

        )


        return add_security_headers(
            response
        )


    except Exception as error:

        print(
            "[!] Challenge verification error:",
            error
        )


        response = jsonify(
            {
                "success": False,
                "error":
                    "Verification error"
            }
        )


        return (
            add_security_headers(
                response
            ),
            500
        )


# ============================================================
# CHECK CHALLENGE COOKIE
# ============================================================

def has_valid_challenge():

    token = request.cookies.get(
        "HAWK_CHALLENGE"
    )


    if not token:

        return False


    result = challenge.verify_token(
        token
    )


    if not result:

        return False


    return True


# ============================================================
# MAIN PROXY
# ============================================================

@app.route(
    "/",
    defaults={
        "path": ""
    },
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD"
    ]
)

@app.route(
    "/<path:path>",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD"
    ]
)

def proxy(path):

    # Reload admin-controlled security settings
    # whenever config.json has changed.
    reload_runtime_config()

    start_time = time.time()

    request_id = (
        "HAWK-"
        + secrets.token_hex(8).upper()
    )

    request.environ["hawk_request_id"] = request_id


    # ========================================================
    # SOURCE IP
    # ========================================================

    source_ip = (
        request.remote_addr
        or "unknown"
    )


    # ========================================================
    # USER AGENT
    # ========================================================

    user_agent = request.headers.get(
        "User-Agent",
        ""
    )


    # ========================================================
    # PROTECTED WEBSITE
    # ========================================================

    requested_host = request.headers.get(
        "Host",
        ""
    )

    selected_site = website_registry.get_site(
        requested_host
    )

    if not selected_site:

        processing_time = (
            (time.time() - start_time)
            * 1000
        )

        log_event(
            source_ip=source_ip,
            method=request.method,
            path=request.full_path,
            rule="UNKNOWN_WEBSITE",
            severity="HIGH",
            action="BLOCK",
            user_agent=user_agent,
            status_code=421,
            processing_time_ms=round(
                processing_time,
                2
            ),
            request_size=0,
            matched_pattern=requested_host
        )

        response = jsonify({
            "error": "Unknown website",
            "message":
                "The requested website is not registered with HAWK WAF",
            "waf": "HAWK WAF"
        })

        response.status_code = 421

        return add_security_headers(
            response
        )

    site_domain = selected_site["domain"]

    request.environ["hawk_site_domain"] = site_domain

    site_policy = website_registry.resolve_policy(
        site_domain
    ) or {}

    request.environ[
        "hawk_security_headers"
    ] = site_policy.get(
        "security_headers",
        {}
    )

    # ========================================================
    # PER-SITE REQUEST SECURITY
    # ========================================================

    site_request_security = site_policy.get(
        "request_security",
        {}
    )

    if not isinstance(
        site_request_security,
        dict
    ):
        site_request_security = {}

    try:
        site_max_body_size = max(
            1,
            int(
                site_request_security.get(
                    "max_body_size",
                    MAX_BODY_SIZE
                )
            )
        )
    except (TypeError, ValueError):
        site_max_body_size = MAX_BODY_SIZE

    site_allowed_methods = site_request_security.get(
        "allowed_methods",
        ALLOWED_METHODS
    )

    if not isinstance(
        site_allowed_methods,
        list
    ) and not isinstance(
        site_allowed_methods,
        set
    ):
        site_allowed_methods = ALLOWED_METHODS

    site_allowed_methods = {
        str(method).strip().upper()
        for method in site_allowed_methods
        if str(method).strip()
    }

    if not site_allowed_methods:
        site_allowed_methods = set(
            ALLOWED_METHODS
        )

    try:
        site_upstream_timeout = max(
            1,
            int(
                site_request_security.get(
                    "upstream_timeout",
                    UPSTREAM_TIMEOUT
                )
            )
        )
    except (TypeError, ValueError):
        site_upstream_timeout = UPSTREAM_TIMEOUT

    # ========================================================
    # HTTP METHOD CONTROL
    # ========================================================

    if request.method.upper() not in site_allowed_methods:

        processing_time = (
            (time.time() - start_time)
            * 1000
        )

        log_event(
            source_ip=source_ip,
            method=request.method,
            path=request.full_path,
            rule="REQUEST_METHOD_NOT_ALLOWED",
            severity="MEDIUM",
            action="BLOCK",
            user_agent=user_agent,
            status_code=405,
            processing_time_ms=round(
                processing_time,
                2
            ),
            request_size=0,
            matched_pattern=request.method
        )

        response = jsonify({
            "error": "Method Not Allowed",
            "message":
                "The requested HTTP method is not allowed",
            "waf": "HAWK WAF",
            "method": request.method,
            "allowed_methods":
                sorted(site_allowed_methods)
        })

        response.status_code = 405

        response.headers["Allow"] = ", ".join(
            sorted(site_allowed_methods)
        )

        return add_security_headers(
            response
        )

    # ========================================================
    # REQUEST SIZE PRE-CHECK
    # ========================================================

    content_length = request.content_length

    if (
        content_length is not None
        and content_length > site_max_body_size
    ):

        processing_time = (
            (time.time() - start_time)
            * 1000
        )

        log_event(
            source_ip=source_ip,
            method=request.method,
            path=request.full_path,
            rule="REQUEST_BODY_TOO_LARGE",
            severity="MEDIUM",
            action="BLOCK",
            user_agent=user_agent,
            status_code=413,
            processing_time_ms=round(
                processing_time,
                2
            ),
            request_size=content_length,
            matched_pattern=(
                f"{content_length}>"
                f"{site_max_body_size}"
            )
        )

        response = jsonify({
            "error": "Request Entity Too Large",
            "message":
                "Request body exceeds the configured maximum size",
            "waf": "HAWK WAF",
            "max_body_size":
                site_max_body_size
        })

        response.status_code = 413

        return add_security_headers(
            response
        )

    site_rate_policy = site_policy.get(
        "rate_limit",
        {}
    )

    site_rate_enabled = bool(
        site_rate_policy.get(
            "enabled",
            RATE_LIMIT_ENABLED
        )
    )

    try:
        site_rate_max = max(
            1,
            int(
                site_rate_policy.get(
                    "max_requests",
                    RATE_LIMIT_MAX
                )
            )
        )
    except (TypeError, ValueError):
        site_rate_max = RATE_LIMIT_MAX

    try:
        site_rate_window = max(
            1,
            int(
                site_rate_policy.get(
                    "window_seconds",
                    RATE_LIMIT_WINDOW
                )
            )
        )
    except (TypeError, ValueError):
        site_rate_window = RATE_LIMIT_WINDOW

    # ========================================================
    # RATE LIMIT
    # ========================================================

    if site_rate_enabled:

        rate_limit_key = (
            f"{site_domain}|{source_ip}"
        )

        if not rate_limiter.is_allowed(
            rate_limit_key,
            max_requests=site_rate_max,
            window_seconds=site_rate_window
        ):

            processing_time = (
                (time.time() - start_time)
                * 1000
            )

            log_event(
                source_ip=source_ip,
                method=request.method,
                path=request.full_path,
                rule="RATE_LIMIT",
                severity="MEDIUM",
                action="RATE_LIMIT",
                user_agent=user_agent,
                status_code=429,
                processing_time_ms=round(
                    processing_time,
                    2
                ),
                request_size=0,
                matched_pattern=(
                    f"{site_domain}:"
                    f"{site_rate_max}/"
                    f"{site_rate_window}s"
                )
            )

            response = jsonify({
                "error":
                    "Too many requests",

                "message":
                    "Rate limit exceeded",

                "retry_after":
                    site_rate_window,

                "website":
                    site_domain
            })

            response.status_code = 429

            response.headers[
                "Retry-After"
            ] = str(
                site_rate_window
            )

            return add_security_headers(
                response
            )

    # ========================================================
    # REQUEST BODY
    # ========================================================

    try:

        body = request.get_data(
            cache=True
        )

    except Exception:

        body = b""


    request_size = len(
        body
    )

    # ========================================================
    # REQUEST SIZE POST-CHECK
    # ========================================================

    if request_size > site_max_body_size:

        processing_time = (
            (time.time() - start_time)
            * 1000
        )

        log_event(
            source_ip=source_ip,
            method=request.method,
            path=request.full_path,
            rule="REQUEST_BODY_TOO_LARGE",
            severity="MEDIUM",
            action="BLOCK",
            user_agent=user_agent,
            status_code=413,
            processing_time_ms=round(
                processing_time,
                2
            ),
            request_size=request_size,
            matched_pattern=(
                f"{request_size}>"
                f"{site_max_body_size}"
            )
        )

        response = jsonify({
            "error": "Request Entity Too Large",
            "message":
                "Request body exceeds the configured maximum size",
            "waf": "HAWK WAF",
            "max_body_size":
                site_max_body_size
        })

        response.status_code = 413

        return add_security_headers(
            response
        )


    try:

        body_text = body.decode(
            "utf-8",
            errors="ignore"
        )

    except Exception:

        body_text = ""


    # ========================================================
    # QUERY STRING
    # ========================================================

    query_string = unquote_plus(
        request.query_string.decode(
            "utf-8",
            errors="ignore"
        )
    )


    # ========================================================
    # HEADERS
    # ========================================================

    headers_text = "\n".join(

        f"{key}: {value}"

        for key, value
        in request.headers.items()

    )


    # ========================================================
    # WAF INSPECTION DATA
    # ========================================================

    inspection_data = (

        request.path

        + "\n"

        + query_string

        + "\n"

        + headers_text

        + "\n"

        + body_text

    )


    # ========================================================
    # PER-SITE WAF RULE POLICY
    # ========================================================

    site_waf_rules = site_policy.get(
        "waf_rules",
        {}
    )

    if not isinstance(
        site_waf_rules,
        dict
    ):
        site_waf_rules = {}

    # ========================================================
    # ATTACK DETECTION
    # ========================================================

    detection = detector.detect(
        inspection_data,
        rule_overrides=site_waf_rules
    )


    if detection.blocked:

        processing_time = (
            (time.time() - start_time)
            * 1000
        )


        log_event(

            source_ip=source_ip,

            method=request.method,

            path=request.full_path,

            rule=detection.rule,

            severity=detection.severity,

            action="BLOCK",

            user_agent=user_agent,

            status_code=403,

            processing_time_ms=
                round(
                    processing_time,
                    2
                ),

            request_size=request_size,

            matched_pattern=
                detection.matched_pattern

        )


        response = jsonify(
            {
                "error":
                    "Request blocked",

                "waf":
                    "HAWK WAF",

                "rule":
                    detection.rule,

                "severity":
                    detection.severity,

                "message":
                    "Malicious request detected"
            }
        )


        response.status_code = 403


        return add_security_headers(
            response
        )


    # ========================================================
    # PER-SITE BOT PROTECTION
    # ========================================================

    site_bot_policy = site_policy.get(
        "bot_protection",
        {}
    )

    site_bot_enabled = bool(
        site_bot_policy.get(
            "enabled",
            BOT_PROTECTION_ENABLED
        )
    )

    site_bot_mode = str(
        site_bot_policy.get(
            "mode",
            BOT_MODE
        )
    ).lower()

    if site_bot_mode not in (
        "block",
        "challenge",
        "log"
    ):
        site_bot_mode = BOT_MODE

    try:
        site_bot_window = max(
            1,
            int(
                site_bot_policy.get(
                    "request_window",
                    BOT_REQUEST_WINDOW
                )
            )
        )
    except (TypeError, ValueError):
        site_bot_window = BOT_REQUEST_WINDOW

    try:
        site_bot_max = max(
            1,
            int(
                site_bot_policy.get(
                    "max_requests",
                    BOT_MAX_REQUESTS
                )
            )
        )
    except (TypeError, ValueError):
        site_bot_max = BOT_MAX_REQUESTS

    # Keep bot history isolated per protected website.
    bot_tracking_key = (
        f"{site_domain}|{source_ip}"
    )

    # ========================================================
    # BOT DETECTION
    # ========================================================

    bot_result = {
        "risk_score": 0,
        "decision": "ALLOW",
        "reasons": [],
        "request_count": 0
    }

    if site_bot_enabled:

        bot_result = bot_detector.analyze(
            ip=bot_tracking_key,
            user_agent=user_agent,
            headers=request.headers,
            path=request.path,
            request_window=site_bot_window,
            max_requests=site_bot_max
        )

        print(
            f"[BOT] "
            f"Website={site_domain} "
            f"IP={source_ip} "
            f"Score={bot_result['risk_score']} "
            f"Decision={bot_result['decision']} "
            f"Reasons={bot_result['reasons']}"
        )

    # ========================================================
    # BOT DECISION
    # ========================================================

    if site_bot_enabled:

        bot_decision = bot_result["decision"]

        # ----------------------------------------------------
        # BOT BLOCK MODE
        # ----------------------------------------------------

        if (
            site_bot_mode == "block"
            and
            bot_decision in [
                "BLOCK",
                "CHALLENGE"
            ]
        ):

            processing_time = (
                (time.time() - start_time)
                * 1000
            )

            log_event(
                source_ip=source_ip,
                method=request.method,
                path=request.full_path,
                rule="BOT_DETECTION",
                severity="HIGH",
                action="BLOCK",
                user_agent=user_agent,
                status_code=403,
                processing_time_ms=round(
                    processing_time,
                    2
                ),
                request_size=request_size,
                matched_pattern=",".join(
                    bot_result["reasons"]
                ),
                bot_score=bot_result["risk_score"],
                bot_decision=bot_result["decision"],
                bot_reasons=bot_result["reasons"]
            )

            response = jsonify({
                "error": "Request blocked",
                "waf": "HAWK WAF",
                "reason":
                    "Automated or suspicious traffic detected",
                "website": site_domain,
                "risk_score":
                    bot_result["risk_score"],
                "reasons":
                    bot_result["reasons"]
            })

            response.status_code = 403

            return add_security_headers(
                response
            )

        # ----------------------------------------------------
        # BOT CHALLENGE MODE
        # ----------------------------------------------------

        if (
            site_bot_mode == "challenge"
            and
            bot_decision == "BLOCK"
        ):

            processing_time = (
                (time.time() - start_time)
                * 1000
            )

            log_event(
                source_ip=source_ip,
                method=request.method,
                path=request.full_path,
                rule="BOT_DETECTION",
                severity="HIGH",
                action="BLOCK",
                user_agent=user_agent,
                status_code=403,
                processing_time_ms=round(
                    processing_time,
                    2
                ),
                request_size=request_size,
                matched_pattern=",".join(
                    bot_result["reasons"]
                ),
                bot_score=bot_result["risk_score"],
                bot_decision=bot_result["decision"],
                bot_reasons=bot_result["reasons"]
            )

            response = jsonify({
                "error": "Request blocked",
                "waf": "HAWK WAF",
                "reason": "High bot risk",
                "website": site_domain,
                "risk_score":
                    bot_result["risk_score"],
                "reasons":
                    bot_result["reasons"]
            })

            response.status_code = 403

            return add_security_headers(
                response
            )

    # ========================================================
    # PER-SITE BROWSER VERIFICATION
    # ========================================================

    site_browser_policy = site_policy.get(
        "browser_verification",
        {}
    )

    site_challenge_enabled = bool(
        site_browser_policy.get(
            "enabled",
            CHALLENGE_ENABLED
        )
    )

    site_challenge_mode = str(
        site_browser_policy.get(
            "mode",
            CHALLENGE_MODE
        )
    ).lower()

    if site_challenge_mode not in (
        "always",
        "suspicious"
    ):
        site_challenge_mode = CHALLENGE_MODE

    # ========================================================
    # CHALLENGE DECISION
    # ========================================================

    should_challenge = False

    if site_challenge_enabled:

        # ----------------------------------------------------
        # ALWAYS
        # ----------------------------------------------------

        if site_challenge_mode == "always":

            should_challenge = True

        # ----------------------------------------------------
        # SUSPICIOUS
        # ----------------------------------------------------

        elif site_challenge_mode == "suspicious":

            if site_bot_enabled:

                if (
                    bot_result["decision"]
                    == "CHALLENGE"
                ):
                    should_challenge = True

            if not user_agent:
                should_challenge = True

            if not request.headers.get(
                "Accept"
            ):
                should_challenge = True

    # ========================================================
    # VALID CHALLENGE COOKIE
    # ========================================================

    if has_valid_challenge():

        should_challenge = False


    # ========================================================
    # SEND CHALLENGE
    # ========================================================

    if should_challenge:

        challenge_url = (
            build_challenge_url()
        )


        processing_time = (
            (time.time() - start_time)
            * 1000
        )


        log_event(

            source_ip=source_ip,

            method=request.method,

            path=request.full_path,

            rule="BOT_CHALLENGE",

            severity="MEDIUM",

            action="CHALLENGE",

            user_agent=user_agent,

            status_code=302,

            processing_time_ms=
                round(
                    processing_time,
                    2
                ),

            request_size=request_size,

            matched_pattern=",".join(
                bot_result["reasons"]
            ),

            bot_score=
                bot_result["risk_score"],

            bot_decision=
                bot_result["decision"],

            bot_reasons=
                bot_result["reasons"]

        )


        response = Response(
            "",
            status=302
        )


        response.headers[
            "Location"
        ] = challenge_url


        return add_security_headers(
            response
        )


    # ========================================================
    # FORWARD TO BACKEND
    # ========================================================

    # ========================================================
    # WEBSITE ROUTING
    # ========================================================

    requested_host = request.headers.get(
        "Host",
        ""
    )

    selected_origin = website_registry.resolve_origin(
        requested_host
    )

    if not selected_origin:

        processing_time = (
            (time.time() - start_time)
            * 1000
        )

        log_event(
            source_ip=source_ip,
            method=request.method,
            path=request.full_path,
            rule="UNKNOWN_WEBSITE",
            severity="HIGH",
            action="BLOCK",
            user_agent=user_agent,
            status_code=421,
            processing_time_ms=round(
                processing_time,
                2
            ),
            request_size=request_size,
            matched_pattern=requested_host,
            bot_score=bot_result["risk_score"],
            bot_decision=bot_result["decision"],
            bot_reasons=bot_result["reasons"]
        )

        response = jsonify({
            "error": "Unknown website",
            "message": "The requested website is not registered with HAWK WAF",
            "waf": "HAWK WAF"
        })

        response.status_code = 421

        return add_security_headers(
            response
        )

    target_url = (
        selected_origin
        + request.path
    )


    if request.query_string:

        target_url += (
            "?"
            + query_string
        )


    # ========================================================
    # FORWARD HEADERS
    # ========================================================

    forwarded_headers = {}


    for key, value in request.headers:

        if key.lower() in [
            "host",
            "content-length",
            "connection"
        ]:

            continue


        forwarded_headers[
            key
        ] = value


    forwarded_headers[
        "X-HAWK-WAF"
    ] = "HAWK WAF"


    forwarded_headers[
        "X-Request-ID"
    ] = request_id


    forwarded_headers[
        "X-Forwarded-For"
    ] = source_ip


    forwarded_headers[
        "X-HAWK-Bot-Score"
    ] = str(
        bot_result["risk_score"]
    )


    forwarded_headers[
        "X-HAWK-Bot-Decision"
    ] = str(
        bot_result["decision"]
    )


    # ========================================================
    # BACKEND REQUEST
    # ========================================================

    try:

        backend_response = requests.request(

            method=request.method,

            url=target_url,

            headers=forwarded_headers,

            data=body,

            cookies=request.cookies,

            allow_redirects=False,

            timeout=site_upstream_timeout

        )


    except requests.RequestException as error:

        processing_time = (
            (time.time() - start_time)
            * 1000
        )


        print(
            "[!] Backend connection error:",
            error
        )


        log_event(

            source_ip=source_ip,

            method=request.method,

            path=request.full_path,

            rule="BACKEND_ERROR",

            severity="HIGH",

            action="ERROR",

            user_agent=user_agent,

            status_code=502,

            processing_time_ms=
                round(
                    processing_time,
                    2
                ),

            request_size=request_size,

            matched_pattern=None,

            bot_score=
                bot_result["risk_score"],

            bot_decision=
                bot_result["decision"],

            bot_reasons=
                bot_result["reasons"]

        )


        response = jsonify(
            {
                "error":
                    "Backend unavailable",

                "waf":
                    "HAWK WAF"
            }
        )


        response.status_code = 502


        return add_security_headers(
            response
        )


    # ========================================================
    # RESPONSE HEADERS
    # ========================================================

    excluded_headers = {

        "content-encoding",

        "content-length",

        "transfer-encoding",

        "connection",

        "server",

        "date"

    }


    response_headers = {}


    for key, value in backend_response.headers.items():

        if key.lower() in excluded_headers:

            continue


        response_headers[
            key
        ] = value


    # ========================================================
    # CREATE RESPONSE
    # ========================================================

    response = Response(

        backend_response.content,

        status=
            backend_response.status_code,

        headers=
            response_headers

    )


    response = add_security_headers(
        response
    )


    # ========================================================
    # LOG ALLOWED REQUEST
    # ========================================================

    processing_time = (
        (time.time() - start_time)
        * 1000
    )


    log_event(

        source_ip=source_ip,

        method=request.method,

        path=request.full_path,

        rule="NONE",

        severity="LOW",

        action="ALLOW",

        user_agent=user_agent,

        status_code=
            backend_response.status_code,

        processing_time_ms=
            round(
                processing_time,
                2
            ),

        request_size=request_size,

        matched_pattern=None,

        bot_score=
            bot_result["risk_score"],

        bot_decision=
            bot_result["decision"],

        bot_reasons=
            bot_result["reasons"]

    )


    return response


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/__hawk_health",
    methods=["GET"]
)

def hawk_health():
    reload_runtime_config()


    response = jsonify(

        {

            "status":
                "healthy",

            "waf":
                "HAWK WAF",

            "version":
                "2.0",

            "backend":
                BACKEND_URL,

            "challenge_enabled":
                CHALLENGE_ENABLED,

            "challenge_mode":
                CHALLENGE_MODE,

            "bot_protection":
                BOT_PROTECTION_ENABLED,

            "bot_mode":
                BOT_MODE,

            "attack_detection":
                True

        }

    )


    return add_security_headers(
        response
    )


# ============================================================
# START HAWK WAF
# ============================================================

if __name__ == "__main__":

    print()

    print("=" * 60)

    print(
        "                 HAWK WAF"
    )

    print(
        "       Web Application Firewall"
    )

    print("=" * 60)

    print()

    print(
        f"[+] WAF              : "
        f"http://{WAF_HOST}:{WAF_PORT}"
    )

    print(
        f"[+] Backend          : "
        f"{BACKEND_URL}"
    )

    print(
        f"[+] Rate Limit       : "
        f"{RATE_LIMIT_MAX} requests / "
        f"{RATE_LIMIT_WINDOW} seconds"
    )

    print(
        f"[+] Challenge        : "
        f"{CHALLENGE_ENABLED}"
    )

    print(
        f"[+] Challenge Mode   : "
        f"{CHALLENGE_MODE}"
    )

    print(
        f"[+] Token Lifetime   : "
        f"{CHALLENGE_TOKEN_LIFETIME} seconds"
    )

    print(
        f"[+] Bot Protection   : "
        f"{BOT_PROTECTION_ENABLED}"
    )

    print(
        f"[+] Bot Mode         : "
        f"{BOT_MODE}"
    )

    print(
        f"[+] Bot Rate Window  : "
        f"{BOT_REQUEST_WINDOW} seconds"
    )

    print(
        f"[+] Bot Max Requests : "
        f"{BOT_MAX_REQUESTS}"
    )

    print(
        "[+] Attack Detection : ENABLED"
    )

    print()

    print("=" * 60)

    print()


    app.run(

        host=WAF_HOST,

        port=WAF_PORT,

        debug=False

    )
