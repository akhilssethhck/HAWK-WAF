import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from flask import has_request_context, request
except ImportError:
    has_request_context = None
    request = None


LOG_FILE = Path(
    "logs/waf_events.json"
)


def generate_event_id():

    return (
        "HAWK-"
        + uuid.uuid4()
        .hex[:12]
        .upper()
    )


def _request_context_value(
    key,
    default=None
):

    if (
        has_request_context is None
        or not has_request_context()
        or request is None
    ):
        return default

    return request.environ.get(
        key,
        default
    )


def log_event(
    source_ip,
    method,
    path,
    rule,
    severity,
    action,
    user_agent="",
    status_code=None,
    processing_time_ms=None,
    request_size=0,
    matched_pattern=None,
    bot_score=None,
    bot_decision=None,
    bot_reasons=None,
    response_size=None,
    upstream_latency_ms=None
):

    event = {

        "event_id":
            generate_event_id(),

        "request_id":
            _request_context_value(
                "hawk_request_id"
            ),

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "source_ip":
            source_ip,

        "host":
            _request_context_value(
                "HTTP_HOST",
                ""
            ),

        "site_domain":
            _request_context_value(
                "hawk_site_domain"
            ),

        "method":
            method,

        "path":
            path,

        "rule":
            rule,

        "matched_pattern":
            matched_pattern,

        "severity":
            severity,

        "action":
            action,

        "status_code":
            status_code,

        "processing_time_ms":
            processing_time_ms,

        "upstream_latency_ms":
            upstream_latency_ms,

        "request_size_bytes":
            request_size,

        "response_size_bytes":
            response_size,

        "user_agent":
            user_agent,

        "bot_score":
            bot_score,

        "bot_decision":
            bot_decision,

        "bot_reasons":
            bot_reasons or []

    }


    LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )


    with open(
        LOG_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(
                event
            )
            + "\n"
        )


    return event
