from flask import Flask, render_template, jsonify, request
import json
import time
import os
import ipaddress
import socket
from urllib.parse import urlparse
from pathlib import Path
from collections import Counter
from waf.admin import HAWKAdmin


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = BASE_DIR / "logs" / "waf_events.json"
CONFIG_FILE = BASE_DIR / "config.json"
RULES_FILE = BASE_DIR / "rules" / "rules.json"
AUDIT_FILE = BASE_DIR / "logs" / "admin_audit.json"


# ============================================================
# FILE HELPERS
# ============================================================

def load_events():
    events = []

    if not LOG_FILE.exists():
        return events

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    except OSError:
        return events

    return events


def load_config():
    if not CONFIG_FILE.exists():
        return {}

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (OSError, json.JSONDecodeError):
        return {}


def save_config(configuration):
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

        with open(CONFIG_FILE, "w", encoding="utf-8") as file:
            json.dump(
                configuration,
                file,
                indent=4
            )

        return True

    except OSError:
        return False


def load_rules():
    if not RULES_FILE.exists():
        return {}

    try:
        with open(RULES_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (OSError, json.JSONDecodeError):
        return {}


def save_rules(rules):
    try:
        RULES_FILE.parent.mkdir(parents=True, exist_ok=True)

        with open(RULES_FILE, "w", encoding="utf-8") as file:
            json.dump(
                rules,
                file,
                indent=4
            )

        return True

    except OSError:
        return False


def load_audit():
    if not AUDIT_FILE.exists():
        return []

    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

            if isinstance(data, list):
                return data

            return []

    except (OSError, json.JSONDecodeError):
        return []


def save_audit(entries):
    try:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)

        with open(AUDIT_FILE, "w", encoding="utf-8") as file:
            json.dump(
                entries,
                file,
                indent=4
            )

        return True

    except OSError:
        return False


# ============================================================
# ADMIN CONFIGURATION
# ============================================================

def load_admin_config():
    configuration = load_config()

    admin_config = configuration.get("admin", {})

    if not isinstance(admin_config, dict):
        admin_config = {}

    return admin_config


ADMIN_CONFIG = load_admin_config()

ADMIN_ENABLED = ADMIN_CONFIG.get("enabled", True)
ADMIN_USERNAME = ADMIN_CONFIG.get("username", "admin")

ADMIN_PASSWORD = os.environ.get(
    "HAWK_ADMIN_PASSWORD",
    ""
)

if ADMIN_ENABLED and not ADMIN_PASSWORD:
    raise RuntimeError(
        "HAWK_ADMIN_PASSWORD environment variable is required."
    )

ADMIN_SESSION_LIFETIME = int(
    ADMIN_CONFIG.get("session_lifetime", 3600)
)


# ============================================================
# ADMIN MANAGER
# ============================================================

admin_manager = HAWKAdmin(
    username=ADMIN_USERNAME,
    password=ADMIN_PASSWORD,
    session_lifetime=ADMIN_SESSION_LIFETIME
)


# ============================================================
# ADMIN HELPERS
# ============================================================

def get_admin_ip():
    forwarded = request.headers.get("X-Forwarded-For")

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.remote_addr or "unknown"


def get_admin_token():
    return request.cookies.get("hawk_admin_session")


def require_admin():

    if not ADMIN_ENABLED:

        return False, "Admin interface disabled"

    token = get_admin_token()

    if not token:

        return False, "Authentication required"

    try:

        valid = admin_manager.verify_session(
            token,
            get_admin_ip()
        )

        if not valid:

            return False, "Invalid or expired session"

        return True, None

    except Exception:

        return False, "Authentication error"

def log_admin_action(action, details=None):
    entries = load_audit()

    entry = {
        "timestamp": int(time.time()),
        "time": time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime()
        ),
        "ip": get_admin_ip(),
        "action": action,
        "details": details or {}
    }

    entries.append(entry)

    # Keep the audit file manageable.
    if len(entries) > 5000:
        entries = entries[-5000:]

    save_audit(entries)


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/admin")
def admin_page():
    return render_template("admin.html")


@app.route("/admin/panel")
def admin_panel():
    authenticated, error = require_admin()

    if not authenticated:
        return render_template("admin.html")

    return render_template("admin_panel.html")

# ============================================================
# MAIN DASHBOARD
# ============================================================

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

# ============================================================
# ADMIN LOGIN
# ============================================================

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    if not ADMIN_ENABLED:
        return jsonify({
            "success": False,
            "error": "Admin interface disabled"
        }), 403

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        data = {}

    username = str(data.get("username", ""))
    password = str(data.get("password", ""))

    try:
        token = admin_manager.login(
            username,
            password,
            get_admin_ip()
        )

    except Exception:
        token = None

    if not token:
        log_admin_action(
            "LOGIN_FAILED",
            {
                "username": username
            }
        )

        return jsonify({
            "success": False,
            "error": "Invalid username or password"
        }), 401

    log_admin_action(
        "LOGIN_SUCCESS",
        {
            "username": username
        }
    )

    response = jsonify({
        "success": True,
        "message": "Login successful"
    })

    response.set_cookie(
        "hawk_admin_session",
        token,
        httponly=True,
        samesite="Strict",
        secure=False,
        max_age=ADMIN_SESSION_LIFETIME
    )

    return response


# ============================================================
# ADMIN LOGOUT
# ============================================================

@app.route("/api/admin/logout", methods=["POST"])
def admin_logout():
    token = get_admin_token()

    if token:
        try:
            admin_manager.logout(token)
        except Exception:
            pass

    log_admin_action("LOGOUT")

    response = jsonify({
        "success": True
    })

    response.delete_cookie("hawk_admin_session")

    return response


# ============================================================
# ADMIN STATUS
# ============================================================

@app.route("/api/admin/status")
def admin_status():
    if not ADMIN_ENABLED:
        return jsonify({
            "authenticated": False,
            "enabled": False
        })

    token = get_admin_token()

    if not token:
        return jsonify({
            "authenticated": False,
            "enabled": True
        })

    try:
        valid = admin_manager.validate_session(token)
    except Exception:
        valid = False

    return jsonify({
        "authenticated": bool(valid),
        "enabled": True
    })


# ============================================================
# ADMIN RULE TOGGLE
# ============================================================

@app.route(
    "/api/admin/rules/<rule_name>",
    methods=["POST"]
)
def admin_rule_toggle(rule_name):
    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    rules = load_rules()

    if rule_name not in rules:
        return jsonify({
            "success": False,
            "error": "Rule not found"
        }), 404

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        data = {}

    enabled = data.get("enabled")

    if not isinstance(enabled, bool):
        return jsonify({
            "success": False,
            "error": "enabled must be true or false"
        }), 400

    if isinstance(rules[rule_name], dict):
        rules[rule_name]["enabled"] = enabled
    else:
        return jsonify({
            "success": False,
            "error": "Invalid rule format"
        }), 500

    if not save_rules(rules):
        return jsonify({
            "success": False,
            "error": "Unable to save rules"
        }), 500

    log_admin_action(
        "RULE_CHANGED",
        {
            "rule": rule_name,
            "enabled": enabled
        }
    )

    return jsonify({
        "success": True,
        "rule": rule_name,
        "enabled": enabled
    })


# ============================================================
# ADMIN BOT CONFIGURATION
# ============================================================

@app.route(
    "/api/admin/bot",
    methods=["POST"]
)
def admin_bot_config():
    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON"
        }), 400

    configuration = load_config()

    bot_config = configuration.setdefault(
        "bot_protection",
        {}
    )

    allowed_fields = [
        "enabled",
        "mode",
        "request_window",
        "max_requests"
    ]

    changes = {}

    for field in allowed_fields:
        if field in data:
            bot_config[field] = data[field]
            changes[field] = data[field]

    if not save_config(configuration):
        return jsonify({
            "success": False,
            "error": "Unable to save configuration"
        }), 500

    log_admin_action(
        "BOT_CONFIG_CHANGED",
        changes
    )

    return jsonify({
        "success": True,
        "bot_protection": bot_config
    })


# ============================================================
# ADMIN BACKEND CONFIGURATION
# ============================================================

@app.route(
    "/api/admin/backend",
    methods=["POST"]
)
def admin_backend_config():

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON"
        }), 400

    configuration = load_config()

    backend_config = configuration.setdefault(
        "backend",
        {}
    )

    changes = {}

    if "host" in data:

        host = str(data["host"]).strip()

        if not host:
            return jsonify({
                "success": False,
                "error": "Backend host cannot be empty"
            }), 400

        if len(host) > 253:
            return jsonify({
                "success": False,
                "error": "Backend host is too long"
            }), 400

        backend_config["host"] = host
        changes["host"] = host

    if "port" in data:

        try:
            port = int(data["port"])
        except (TypeError, ValueError):

            return jsonify({
                "success": False,
                "error": "Backend port must be a number"
            }), 400

        if port < 1 or port > 65535:

            return jsonify({
                "success": False,
                "error": "Backend port must be between 1 and 65535"
            }), 400

        backend_config["port"] = port
        changes["port"] = port

    if not changes:

        return jsonify({
            "success": False,
            "error": "No backend configuration supplied"
        }), 400

    if not save_config(configuration):

        return jsonify({
            "success": False,
            "error": "Unable to save configuration"
        }), 500

    log_admin_action(
        "BACKEND_CONFIG_CHANGED",
        changes
    )

    return jsonify({
        "success": True,
        "backend": backend_config
    })


# ============================================================
# PROTECTED WEBSITES MANAGEMENT
# ============================================================

import re
from urllib.parse import urlparse


def validate_website_domain(domain):

    if not isinstance(domain, str):
        return False

    domain = domain.strip().lower()

    if not domain:
        return False

    if len(domain) > 253:
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    # Allow normal DNS names and local lab hostnames.
    if not re.match(
        r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$",
        domain
    ):
        return False

    if ".." in domain:
        return False

    return True


def _origin_security_config():

    configuration = load_config()

    settings = configuration.get(
        "origin_security",
        {}
    )

    if not isinstance(settings, dict):
        settings = {}

    allowed_schemes = settings.get(
        "allowed_schemes",
        ["http", "https"]
    )

    if not isinstance(
        allowed_schemes,
        list
    ):
        allowed_schemes = [
            "http",
            "https"
        ]

    allowed_schemes = {
        str(scheme).strip().lower()
        for scheme in allowed_schemes
        if str(scheme).strip()
    }

    if not allowed_schemes:
        allowed_schemes = {
            "http",
            "https"
        }

    return {
        "enabled": bool(
            settings.get(
                "enabled",
                True
            )
        ),
        "allow_private_origins": bool(
            settings.get(
                "allow_private_origins",
                False
            )
        ),
        "block_metadata_ips": bool(
            settings.get(
                "block_metadata_ips",
                True
            )
        ),
        "allowed_schemes": allowed_schemes
    }


def _is_metadata_ip(ip):

    try:
        address = ipaddress.ip_address(ip)

    except ValueError:
        return False

    metadata_ranges = [
        ipaddress.ip_network(
            "169.254.169.254/32"
        ),
        ipaddress.ip_network(
            "169.254.170.2/32"
        ),
        ipaddress.ip_network(
            "fd00:ec2::254/128"
        )
    ]

    return any(
        address in network
        for network in metadata_ranges
    )


def _is_private_or_restricted_ip(ip):

    try:
        address = ipaddress.ip_address(ip)

    except ValueError:
        return True

    return any([
        address.is_private,
        address.is_loopback,
        address.is_link_local,
        address.is_multicast,
        address.is_unspecified,
        address.is_reserved
    ])


def _resolve_origin_hostname(
    hostname,
    port
):

    try:
        results = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM
        )

    except socket.gaierror:
        return []

    addresses = []

    for result in results:

        sockaddr = result[4]

        if not sockaddr:
            continue

        address = sockaddr[0]

        if address not in addresses:
            addresses.append(address)

    return addresses


def validate_website_origin(origin):

    if not isinstance(origin, str):
        return False

    origin = origin.strip()

    if not origin:
        return False

    if len(origin) > 2048:
        return False

    if any(
        character in origin
        for character in [
            "\r",
            "\n",
            "\t"
        ]
    ):
        return False

    security = _origin_security_config()

    try:

        parsed = urlparse(origin)

        if parsed.scheme.lower() not in (
            security["allowed_schemes"]
        ):
            return False

        if not parsed.hostname:
            return False

        if parsed.username or parsed.password:
            return False

        if parsed.path not in (
            "",
            "/"
        ):
            return False

        if parsed.params:
            return False

        if parsed.query or parsed.fragment:
            return False

        port = parsed.port

        if port is None:

            if parsed.scheme.lower() == "https":
                port = 443

            else:
                port = 80

        if port < 1 or port > 65535:
            return False

    except (
        ValueError,
        TypeError
    ):
        return False

    if not security["enabled"]:
        return True

    hostname = parsed.hostname

    # Direct IP address
    try:

        ip = ipaddress.ip_address(
            hostname
        )

        if (
            security["block_metadata_ips"]
            and _is_metadata_ip(
                str(ip)
            )
        ):
            return False

        if (
            not security["allow_private_origins"]
            and _is_private_or_restricted_ip(
                str(ip)
            )
        ):
            return False

        return True

    except ValueError:
        pass

    # DNS hostname
    addresses = _resolve_origin_hostname(
        hostname,
        port
    )

    if not addresses:
        return False

    for address in addresses:

        if (
            security["block_metadata_ips"]
            and _is_metadata_ip(address)
        ):
            return False

        if (
            not security["allow_private_origins"]
            and _is_private_or_restricted_ip(address)
        ):
            return False

    return True


@app.route(
    "/api/admin/websites",
    methods=["GET"]
)
def admin_list_websites():

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    configuration = load_config()

    websites = configuration.get(
        "websites",
        {}
    )

    if not isinstance(websites, dict):
        websites = {}

    result = []

    for domain, site in websites.items():

        if not isinstance(site, dict):
            continue

        result.append({
            "domain": domain,
            "origin": site.get(
                "origin",
                ""
            ),
            "enabled": bool(
                site.get(
                    "enabled",
                    True
                )
            )
        })

    return jsonify({
        "success": True,
        "websites": result
    })


@app.route(
    "/api/admin/websites",
    methods=["POST"]
)
def admin_add_website():

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON"
        }), 400

    domain = str(
        data.get(
            "domain",
            ""
        )
    ).strip().lower()

    origin = str(
        data.get(
            "origin",
            ""
        )
    ).strip().rstrip("/")

    if not validate_website_domain(
        domain
    ):
        return jsonify({
            "success": False,
            "error": "Invalid website domain"
        }), 400

    if not validate_website_origin(
        origin
    ):
        return jsonify({
            "success": False,
            "error": "Invalid origin URL"
        }), 400

    configuration = load_config()

    websites = configuration.setdefault(
        "websites",
        {}
    )

    if not isinstance(websites, dict):
        websites = {}
        configuration["websites"] = websites

    if domain in websites:
        return jsonify({
            "success": False,
            "error": "Website already exists"
        }), 409

    websites[domain] = {
        "origin": origin,
        "enabled": True
    }

    if not save_config(
        configuration
    ):
        return jsonify({
            "success": False,
            "error": "Unable to save website configuration"
        }), 500

    log_admin_action(
        "WEBSITE_ADDED",
        {
            "domain": domain,
            "origin": origin
        }
    )

    return jsonify({
        "success": True,
        "website": {
            "domain": domain,
            "origin": origin,
            "enabled": True
        }
    }), 201


@app.route(
    "/api/admin/websites/<path:domain>/toggle",
    methods=["POST"]
)
def admin_toggle_website(
    domain
):

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    domain = domain.strip().lower()

    configuration = load_config()

    websites = configuration.get(
        "websites",
        {}
    )

    if (
        not isinstance(websites, dict)
        or domain not in websites
        or not isinstance(
            websites[domain],
            dict
        )
    ):
        return jsonify({
            "success": False,
            "error": "Website not found"
        }), 404

    current_state = bool(
        websites[domain].get(
            "enabled",
            True
        )
    )

    websites[domain]["enabled"] = (
        not current_state
    )

    if not save_config(
        configuration
    ):
        return jsonify({
            "success": False,
            "error": "Unable to save website configuration"
        }), 500

    log_admin_action(
        "WEBSITE_STATUS_CHANGED",
        {
            "domain": domain,
            "enabled":
                not current_state
        }
    )

    return jsonify({
        "success": True,
        "domain": domain,
        "enabled":
            not current_state
    })


@app.route(
    "/api/admin/websites/<path:domain>",
    methods=["DELETE"]
)
def admin_delete_website(
    domain
):

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    domain = domain.strip().lower()

    configuration = load_config()

    websites = configuration.get(
        "websites",
        {}
    )

    if (
        not isinstance(websites, dict)
        or domain not in websites
    ):
        return jsonify({
            "success": False,
            "error": "Website not found"
        }), 404

    removed_site = websites.pop(
        domain
    )

    if not save_config(
        configuration
    ):
        return jsonify({
            "success": False,
            "error": "Unable to save website configuration"
        }), 500

    log_admin_action(
        "WEBSITE_REMOVED",
        {
            "domain": domain,
            "origin":
                removed_site.get(
                    "origin",
                    ""
                )
        }
    )

    return jsonify({
        "success": True,
        "domain": domain
    })


# ============================================================
# ADMIN PER-SITE BOT PROTECTION
# ============================================================


@app.route(
    "/api/admin/websites/<path:domain>/bot",
    methods=["GET"]
)
def admin_get_website_bot(domain):

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    domain = domain.strip().lower()

    configuration = load_config()

    websites = configuration.get(
        "websites",
        {}
    )

    if (
        not isinstance(websites, dict)
        or domain not in websites
        or not isinstance(
            websites[domain],
            dict
        )
    ):
        return jsonify({
            "success": False,
            "error": "Website not found"
        }), 404

    site = websites[domain]

    bot_config = site.get(
        "bot_protection",
        {}
    )

    if not isinstance(
        bot_config,
        dict
    ):
        bot_config = {}

    enabled = bool(
        bot_config.get(
            "enabled",
            True
        )
    )

    mode = str(
        bot_config.get(
            "mode",
            "challenge"
        )
    ).lower()

    if mode not in (
        "block",
        "challenge",
        "log"
    ):
        mode = "challenge"

    try:
        request_window = max(
            1,
            int(
                bot_config.get(
                    "request_window",
                    10
                )
            )
        )
    except (TypeError, ValueError):
        request_window = 10

    try:
        max_requests = max(
            1,
            int(
                bot_config.get(
                    "max_requests",
                    30
                )
            )
        )
    except (TypeError, ValueError):
        max_requests = 30

    return jsonify({
        "success": True,
        "domain": domain,
        "bot_protection": {
            "enabled": enabled,
            "mode": mode,
            "request_window": request_window,
            "max_requests": max_requests
        }
    })


@app.route(
    "/api/admin/websites/<path:domain>/bot",
    methods=["POST"]
)
def admin_website_bot_config(domain):

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    domain = domain.strip().lower()

    configuration = load_config()

    websites = configuration.get(
        "websites",
        {}
    )

    if (
        not isinstance(websites, dict)
        or domain not in websites
        or not isinstance(
            websites[domain],
            dict
        )
    ):
        return jsonify({
            "success": False,
            "error": "Website not found"
        }), 404

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON"
        }), 400

    site = websites[domain]

    bot_config = site.setdefault(
        "bot_protection",
        {}
    )

    if not isinstance(
        bot_config,
        dict
    ):
        bot_config = {}
        site["bot_protection"] = bot_config

    changes = {}

    # --------------------------------------------------------
    # ENABLED
    # --------------------------------------------------------

    if "enabled" in data:

        enabled = data["enabled"]

        if not isinstance(
            enabled,
            bool
        ):
            return jsonify({
                "success": False,
                "error":
                    "enabled must be true or false"
            }), 400

        bot_config["enabled"] = enabled
        changes["enabled"] = enabled

    # --------------------------------------------------------
    # MODE
    # --------------------------------------------------------

    if "mode" in data:

        mode = str(
            data["mode"]
        ).strip().lower()

        if mode not in (
            "block",
            "challenge",
            "log"
        ):
            return jsonify({
                "success": False,
                "error":
                    "mode must be block, challenge, or log"
            }), 400

        bot_config["mode"] = mode
        changes["mode"] = mode

    # --------------------------------------------------------
    # REQUEST WINDOW
    # --------------------------------------------------------

    if "request_window" in data:

        try:
            request_window = int(
                data["request_window"]
            )
        except (TypeError, ValueError):

            return jsonify({
                "success": False,
                "error":
                    "request_window must be an integer"
            }), 400

        if request_window < 1 or request_window > 86400:

            return jsonify({
                "success": False,
                "error":
                    "request_window must be between 1 and 86400"
            }), 400

        bot_config["request_window"] = (
            request_window
        )

        changes["request_window"] = (
            request_window
        )

    # --------------------------------------------------------
    # MAX REQUESTS
    # --------------------------------------------------------

    if "max_requests" in data:

        try:
            max_requests = int(
                data["max_requests"]
            )
        except (TypeError, ValueError):

            return jsonify({
                "success": False,
                "error":
                    "max_requests must be an integer"
            }), 400

        if max_requests < 1 or max_requests > 100000:

            return jsonify({
                "success": False,
                "error":
                    "max_requests must be between 1 and 100000"
            }), 400

        bot_config["max_requests"] = (
            max_requests
        )

        changes["max_requests"] = (
            max_requests
        )

    if not save_config(
        configuration
    ):
        return jsonify({
            "success": False,
            "error":
                "Unable to save website Bot Protection configuration"
        }), 500

    log_admin_action(
        "WEBSITE_BOT_CONFIG_CHANGED",
        {
            "domain": domain,
            "changes": changes
        }
    )

    return jsonify({
        "success": True,
        "domain": domain,
        "bot_protection": bot_config
    })


# ============================================================
# ADMIN PER-SITE WAF RULES
# ============================================================


@app.route(
    "/api/admin/websites/<path:domain>/rules",
    methods=["GET"]
)
def admin_get_website_rules(domain):

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    domain = domain.strip().lower()

    configuration = load_config()

    websites = configuration.get(
        "websites",
        {}
    )

    if (
        not isinstance(websites, dict)
        or domain not in websites
        or not isinstance(
            websites[domain],
            dict
        )
    ):
        return jsonify({
            "success": False,
            "error": "Website not found"
        }), 404

    rules = load_rules()

    site = websites[domain]

    site_overrides = site.get(
        "waf_rules",
        {}
    )

    if not isinstance(
        site_overrides,
        dict
    ):
        site_overrides = {}

    result = {}

    for rule_name, rule_config in rules.items():

        if not isinstance(
            rule_config,
            dict
        ):
            continue

        global_enabled = bool(
            rule_config.get(
                "enabled",
                True
            )
        )

        override = site_overrides.get(
            rule_name
        )

        has_override = isinstance(
            override,
            dict
        ) and "enabled" in override

        effective_enabled = global_enabled

        if has_override:
            effective_enabled = bool(
                override["enabled"]
            )

        result[rule_name] = {
            "enabled": effective_enabled,
            "global_enabled": global_enabled,
            "override": has_override,
            "severity": rule_config.get(
                "severity",
                "HIGH"
            )
        }

    return jsonify({
        "success": True,
        "domain": domain,
        "rules": result
    })


@app.route(
    "/api/admin/websites/<path:domain>/rules/<rule_name>",
    methods=["POST"]
)
def admin_toggle_website_rule(
    domain,
    rule_name
):

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    domain = domain.strip().lower()
    rule_name = rule_name.strip()

    configuration = load_config()

    websites = configuration.get(
        "websites",
        {}
    )

    if (
        not isinstance(websites, dict)
        or domain not in websites
        or not isinstance(
            websites[domain],
            dict
        )
    ):
        return jsonify({
            "success": False,
            "error": "Website not found"
        }), 404

    rules = load_rules()

    if rule_name not in rules:
        return jsonify({
            "success": False,
            "error": "Rule not found"
        }), 404

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON"
        }), 400

    enabled = data.get(
        "enabled"
    )

    if not isinstance(enabled, bool):
        return jsonify({
            "success": False,
            "error":
                "enabled must be true or false"
        }), 400

    site = websites[domain]

    site_overrides = site.setdefault(
        "waf_rules",
        {}
    )

    if not isinstance(
        site_overrides,
        dict
    ):
        site_overrides = {}
        site["waf_rules"] = site_overrides

    site_overrides[rule_name] = {
        "enabled": enabled
    }

    if not save_config(
        configuration
    ):
        return jsonify({
            "success": False,
            "error":
                "Unable to save website rule configuration"
        }), 500

    log_admin_action(
        "WEBSITE_RULE_CHANGED",
        {
            "domain": domain,
            "rule": rule_name,
            "enabled": enabled
        }
    )

    return jsonify({
        "success": True,
        "domain": domain,
        "rule": rule_name,
        "enabled": enabled
    })


@app.route(
    "/api/admin/websites/<path:domain>/rules/<rule_name>",
    methods=["DELETE"]
)
def admin_reset_website_rule(
    domain,
    rule_name
):

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    domain = domain.strip().lower()
    rule_name = rule_name.strip()

    configuration = load_config()

    websites = configuration.get(
        "websites",
        {}
    )

    if (
        not isinstance(websites, dict)
        or domain not in websites
        or not isinstance(
            websites[domain],
            dict
        )
    ):
        return jsonify({
            "success": False,
            "error": "Website not found"
        }), 404

    rules = load_rules()

    if rule_name not in rules:
        return jsonify({
            "success": False,
            "error": "Rule not found"
        }), 404

    site = websites[domain]

    site_overrides = site.get(
        "waf_rules",
        {}
    )

    if not isinstance(
        site_overrides,
        dict
    ):
        site_overrides = {}

    removed = (
        site_overrides.pop(
            rule_name,
            None
        )
        is not None
    )

    if not save_config(
        configuration
    ):
        return jsonify({
            "success": False,
            "error":
                "Unable to save website rule configuration"
        }), 500

    log_admin_action(
        "WEBSITE_RULE_RESET",
        {
            "domain": domain,
            "rule": rule_name
        }
    )

    return jsonify({
        "success": True,
        "domain": domain,
        "rule": rule_name,
        "reset": removed
    })



# ============================================================
# ADMIN RATE LIMIT CONFIGURATION
# ============================================================


@app.route(
    "/api/admin/rate-limit",
    methods=["POST"]
)
def admin_rate_limit_config():
    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON"
        }), 400

    configuration = load_config()

    rate_config = configuration.setdefault(
        "rate_limit",
        {}
    )

    allowed_fields = [
        "enabled",
        "max_requests",
        "window_seconds"
    ]

    changes = {}

    for field in allowed_fields:
        if field in data:
            rate_config[field] = data[field]
            changes[field] = data[field]

    if not save_config(configuration):
        return jsonify({
            "success": False,
            "error": "Unable to save configuration"
        }), 500

    log_admin_action(
        "RATE_LIMIT_CHANGED",
        changes
    )

    return jsonify({
        "success": True,
        "rate_limit": rate_config
    })


# ============================================================
# ADMIN CHALLENGE CONFIGURATION
# ============================================================

@app.route(
    "/api/admin/challenge",
    methods=["POST"]
)
def admin_challenge_config():
    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON"
        }), 400

    configuration = load_config()

    challenge_config = configuration.setdefault(
        "challenge",
        {}
    )

    allowed_fields = [
        "enabled",
        "mode",
        "token_lifetime"
    ]

    changes = {}

    for field in allowed_fields:
        if field in data:
            challenge_config[field] = data[field]
            changes[field] = data[field]

    if not save_config(configuration):
        return jsonify({
            "success": False,
            "error": "Unable to save configuration"
        }), 500

    log_admin_action(
        "CHALLENGE_CONFIG_CHANGED",
        changes
    )

    return jsonify({
        "success": True,
        "challenge": challenge_config
    })


# ============================================================
# ADMIN PER-SITE BROWSER VERIFICATION
# ============================================================


@app.route(
    "/api/admin/websites/<path:domain>/browser-verification",
    methods=["GET"]
)
def admin_get_website_browser(domain):

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    domain = domain.strip().lower()

    configuration = load_config()

    websites = configuration.get(
        "websites",
        {}
    )

    if (
        not isinstance(websites, dict)
        or domain not in websites
        or not isinstance(
            websites[domain],
            dict
        )
    ):
        return jsonify({
            "success": False,
            "error": "Website not found"
        }), 404

    site = websites[domain]

    browser_config = site.get(
        "browser_verification",
        {}
    )

    if not isinstance(
        browser_config,
        dict
    ):
        browser_config = {}

    enabled = bool(
        browser_config.get(
            "enabled",
            False
        )
    )

    mode = str(
        browser_config.get(
            "mode",
            "suspicious"
        )
    ).lower()

    if mode not in (
        "always",
        "suspicious"
    ):
        mode = "suspicious"

    return jsonify({
        "success": True,
        "domain": domain,
        "browser_verification": {
            "enabled": enabled,
            "mode": mode
        }
    })


@app.route(
    "/api/admin/websites/<path:domain>/browser-verification",
    methods=["POST"]
)
def admin_website_browser_config(domain):

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    domain = domain.strip().lower()

    configuration = load_config()

    websites = configuration.get(
        "websites",
        {}
    )

    if (
        not isinstance(websites, dict)
        or domain not in websites
        or not isinstance(
            websites[domain],
            dict
        )
    ):
        return jsonify({
            "success": False,
            "error": "Website not found"
        }), 404

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON"
        }), 400

    site = websites[domain]

    browser_config = site.setdefault(
        "browser_verification",
        {}
    )

    if not isinstance(
        browser_config,
        dict
    ):
        browser_config = {}
        site["browser_verification"] = browser_config

    changes = {}

    # --------------------------------------------------------
    # ENABLED
    # --------------------------------------------------------

    if "enabled" in data:

        enabled = data["enabled"]

        if not isinstance(
            enabled,
            bool
        ):
            return jsonify({
                "success": False,
                "error":
                    "enabled must be true or false"
            }), 400

        browser_config["enabled"] = enabled
        changes["enabled"] = enabled

    # --------------------------------------------------------
    # MODE
    # --------------------------------------------------------

    if "mode" in data:

        mode = str(
            data["mode"]
        ).strip().lower()

        if mode not in (
            "always",
            "suspicious"
        ):
            return jsonify({
                "success": False,
                "error":
                    "mode must be always or suspicious"
            }), 400

        browser_config["mode"] = mode
        changes["mode"] = mode

    if not changes:
        return jsonify({
            "success": False,
            "error":
                "No supported Browser Verification fields supplied"
        }), 400

    if not save_config(
        configuration
    ):
        return jsonify({
            "success": False,
            "error":
                "Unable to save Browser Verification configuration"
        }), 500

    log_admin_action(
        "WEBSITE_BROWSER_VERIFICATION_CHANGED",
        {
            "domain": domain,
            "changes": changes
        }
    )

    return jsonify({
        "success": True,
        "domain": domain,
        "browser_verification":
            browser_config
    })


# ============================================================
# ADMIN AUDIT LOG
# ============================================================

@app.route("/api/admin/audit")
def admin_audit():
    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    entries = load_audit()

    limit = request.args.get(
        "limit",
        default=100,
        type=int
    )

    limit = max(1, min(limit, 1000))

    return jsonify({
        "success": True,
        "events": entries[-limit:]
    })


# ============================================================
# ADMIN SESSION CLEANUP
# ============================================================

@app.route(
    "/api/admin/cleanup",
    methods=["POST"]
)
def admin_cleanup():
    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    try:
        removed = admin_manager.cleanup_sessions()
    except Exception:
        removed = 0

    log_admin_action(
        "SESSION_CLEANUP",
        {
            "removed": removed
        }
    )

    return jsonify({
        "success": True,
        "removed": removed
    })


# ============================================================
# CLEAR SECURITY LOGS
# ============================================================

@app.route(
    "/api/admin/clear-logs",
    methods=["POST"]
)
def admin_clear_logs():

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    try:
        events = load_events()
        removed = len(events)

        LOG_FILE.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(
            LOG_FILE,
            "w",
            encoding="utf-8"
        ) as file:
            file.write("")

        log_admin_action(
            "SECURITY_LOGS_CLEARED",
            {
                "removed": removed
            }
        )

        return jsonify({
            "success": True,
            "removed": removed
        })

    except OSError as error:

        return jsonify({
            "success": False,
            "error": f"Unable to clear security logs: {error}"
        }), 500


# ============================================================
# STATS API
# ============================================================
@app.route("/api/stats")
def api_stats():

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    events = load_events()

    total = len(events)

    allowed = 0
    blocked = 0
    rate_limited = 0
    errors = 0

    high = 0
    medium = 0
    low = 0

    source_ips = Counter()
    attack_types = Counter()
    status_codes = Counter()

    challenged_requests = 0

    for event in events:

        # ----------------------------------------------------
        # ACTION
        # ----------------------------------------------------

        action = str(
            event.get("action", "")
        ).upper()

        if action == "ALLOW":
            allowed += 1

        elif action == "BLOCK":
            blocked += 1

        elif action == "CHALLENGE":
            challenged_requests += 1

        elif action == "RATE_LIMIT":
            rate_limited += 1

        # ----------------------------------------------------
        # STATUS CODE
        # ----------------------------------------------------

        status_code = event.get("status_code")

        if status_code is not None:
            try:
                status_code = int(status_code)

                status_codes[
                    str(status_code)
                ] += 1

            except (TypeError, ValueError):
                status_code = None

        # ----------------------------------------------------
        # ERROR COUNT
        # ----------------------------------------------------
        # Count an event as an error once.
        # A 5xx response is considered an error.
        # Backend-error actions are also considered errors.

        if (
            action in (
                "ERROR",
                "BACKEND_ERROR"
            )
            or (
                status_code is not None
                and status_code >= 500
            )
        ):
            errors += 1

        # ----------------------------------------------------
        # RATE LIMIT COUNT
        # ----------------------------------------------------
        # Count each rate-limited event once, whether identified
        # by action or by HTTP 429.

        if (
            action == "RATE_LIMIT"
            or status_code == 429
        ):
            if action != "RATE_LIMIT":
                rate_limited += 1

        # ----------------------------------------------------
        # SOURCE IP
        # ----------------------------------------------------

        source_ip = (
            event.get("source_ip")
            or event.get("ip")
            or event.get("client_ip")
            or event.get("remote_addr")
        )

        if source_ip:
            source_ips[
                str(source_ip)
            ] += 1

        # ----------------------------------------------------
        # ATTACK TYPE
        # ----------------------------------------------------

        rule = event.get("rule")

        if rule:
            rule = str(rule)

            if rule.upper() not in (
                "NONE",
                ""
            ):
                attack_types[
                    rule
                ] += 1

        # ----------------------------------------------------
        # SEVERITY
        # ----------------------------------------------------

        severity = str(
            event.get("severity", "")
        ).upper()

        if severity == "HIGH":
            high += 1

        elif severity == "MEDIUM":
            medium += 1

        elif severity == "LOW":
            low += 1

    return jsonify({

        # Basic statistics
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "rate_limited": rate_limited,
        "errors": errors,

        # Severity
        "high": high,
        "medium": medium,
        "low": low,

        # Analysis
        "source_ips": dict(source_ips),
        "attack_types": dict(attack_types),
        "status_codes": dict(status_codes),

        # Dashboard compatibility
        "total_requests": total,
        "allowed_requests": allowed,
        "blocked_requests": blocked,
        "challenged_requests": challenged_requests,

        # Rankings
        "top_ips": source_ips.most_common(10),
        "top_rules": attack_types.most_common(10)
    })
# ============================================================
# EVENTS API
# ============================================================

@app.route("/api/events")
def api_events():

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    events = load_events()

    limit = request.args.get(
        "limit",
        default=100,
        type=int
    )

    limit = max(
        1,
        min(limit, 1000)
    )

    # Return the newest events first
    recent_events = list(
        reversed(
            events[-limit:]
        )
    )

    return jsonify({
        "events": recent_events
    })

# ============================================================
# CONFIG API
# ============================================================

@app.route("/api/config")
def api_config():

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    configuration = load_config()

    waf = configuration.get("waf", {})
    backend = configuration.get("backend", {})
    dashboard = configuration.get("dashboard", {})
    rate_limit = configuration.get("rate_limit", {})
    challenge = configuration.get("challenge", {})
    bot_protection = configuration.get("bot_protection", {})

    return jsonify({
        "waf_name": waf.get("name", "HAWK WAF"),
        "waf_host": waf.get("host", "127.0.0.1"),
        "waf_port": waf.get("port", 8080),

        "backend_host": backend.get("host", "127.0.0.1"),
        "backend_port": backend.get("port", 5001),

        "dashboard_host": dashboard.get("host", "127.0.0.1"),
        "dashboard_port": dashboard.get("port", 9000),

        "rate_limit_enabled": rate_limit.get(
            "enabled",
            False
        ),
        "max_requests": rate_limit.get(
            "max_requests",
            20
        ),
        "window_seconds": rate_limit.get(
            "window_seconds",
            10
        ),

        "challenge_enabled": challenge.get(
            "enabled",
            False
        ),
        "challenge_mode": challenge.get(
            "mode",
            "always"
        ),
        "token_lifetime": challenge.get(
            "token_lifetime",
            300
        ),

        "bot_protection_enabled": bot_protection.get(
            "enabled",
            False
        ),
        "bot_protection_mode": bot_protection.get(
            "mode",
            "challenge"
        ),
        "bot_request_window": bot_protection.get(
            "request_window",
            10
        ),
        "bot_max_requests": bot_protection.get(
            "max_requests",
            30
        )
    })

# ============================================================
# RULES API
# ============================================================

@app.route("/api/rules")
def api_rules():

    authenticated, error = require_admin()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": error
        }), 401

    rules = load_rules()

    return jsonify(rules)


# ============================================================
# HEALTH API
# ============================================================

@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "service": "HAWK WAF Dashboard",
        "timestamp": int(time.time())
    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Not found"
    }), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "error": "Internal server error"
    }), 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":
    configuration = load_config()

    dashboard_config = configuration.get(
        "dashboard",
        {}
    )

    host = dashboard_config.get(
        "host",
        "127.0.0.1"
    )

    port = int(
        dashboard_config.get(
            "port",
            9000
        )
    )

    print("=" * 60)
    print("HAWK WAF DASHBOARD")
    print("=" * 60)
    print(f"Dashboard: http://{host}:{port}")
    print(f"Admin:     http://{host}:{port}/admin")
    print("=" * 60)

    app.run(
        host=host,
        port=port,
        debug=False
    )
