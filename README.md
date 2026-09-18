# HAWK WAF

**HAWK WAF** is a Python-based Web Application Firewall (WAF) and reverse proxy designed for authorized security testing and local cybersecurity labs.

It sits between clients and a backend web application, inspecting HTTP requests, applying configurable security policies, blocking suspicious traffic, detecting automated clients, enforcing rate limits, and generating structured security logs.

## Architecture

```text
                    Client
                       |
                       v
                +---------------+
                |    HAWK WAF   |
                |    :8080      |
                +---------------+
                       |
        +--------------+--------------+
        |              |              |
        v              v              v
   Host Validation  WAF Detection  Rate Limiting
        |              |              |
        +--------------+--------------+
                       |
              +--------+--------+
              |                 |
              v                 v
        Bot Detection    Browser Verification
              |                 |
              +--------+--------+
                       |
                       v
                Security Headers
                       |
                       v
                 Request ID
                       |
                       v
                Structured Logs
                       |
                       v
                Backend :5001

              Admin Dashboard :9000
```

## Core Features

### Web Application Firewall

HAWK WAF inspects incoming HTTP requests and applies configurable detection rules.

Current detection categories include:

- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- Suspicious File Access
- Header Injection

Rules are stored in:

```text
rules/rules.json
```

The detection engine supports normalization and multiple levels of URL decoding to help identify encoded malicious input.

### Reverse Proxy

HAWK WAF operates as a reverse proxy between clients and the protected backend application.

```text
Client -> HAWK WAF -> Backend
```

Allowed requests are forwarded to the configured origin while blocked requests are rejected before reaching the backend.

### Multi-Site Routing

Different websites can be protected through host-based routing.

Example:

```text
example.local -> http://127.0.0.1:5001
test.local    -> http://127.0.0.1:5001
```

Each site can have its own security policy.

### Rate Limiting

HAWK WAF supports configurable request limits using a request count and time window.

Example:

```text
20 requests / 10 seconds
```

Different limits can be configured for different protected websites.

### Bot Detection

HAWK WAF includes heuristic bot detection based on request characteristics such as:

- User-Agent
- HTTP headers
- Request paths
- Request frequency

Suspicious automated clients can be blocked or challenged depending on the configured policy.

### Browser Verification

The WAF supports a browser verification challenge for suspicious traffic.

The challenge uses a cryptographic token to verify that the request completed the HAWK browser challenge.

### Request Security

HAWK WAF supports configurable request-security controls including:

- Maximum request body size
- Allowed HTTP methods
- Upstream request timeout
- Host validation
- Origin validation

### Origin Validation

Configured upstream origins are validated before use.

The validation layer supports controls for:

- Allowed URL schemes
- Invalid URLs
- Embedded credentials
- Paths and query strings
- Restricted IP addresses
- Private origins
- Metadata-service addresses
- DNS resolution

Private origins are enabled for the current local laboratory deployment.

For production environments, the origin-security policy should be reviewed and tightened appropriately.

### Security Headers

HAWK WAF can add security-related HTTP response headers such as:

```text
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
Permissions-Policy
Strict-Transport-Security
```

Example response:

```text
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### Request Correlation

Each request can receive a unique HAWK request identifier.

Example:

```text
X-Request-ID: HAWK-978224AC62187ECE
```

The same request ID is stored in the security log, allowing requests and security events to be correlated during analysis.

## Security Logging

HAWK WAF generates structured JSON security events.

Logged information can include:

- Event ID
- Request ID
- Timestamp
- Host
- Protected site
- HTTP status
- Attack type
- Request size
- Response size
- Upstream latency
- Bot-detection information

Example:

```json
{
  "event_id": "event-id",
  "request_id": "HAWK-REQUEST-ID",
  "host": "example.local",
  "site_domain": "example.local",
  "status": 403,
  "attack_type": "XSS"
}
```

Logs are stored locally and are intended to support security monitoring and investigation.

## Administration

HAWK WAF includes an administrative dashboard.

Current administrative capabilities include:

- Authentication
- Session management
- Session expiration
- Logout
- Login rate limiting
- Audit logging
- Security statistics
- WAF events
- Configuration information
- WAF rule information

Administrative APIs are protected by authentication.

## Authentication Security

The administration component uses:

```text
PBKDF2-HMAC-SHA256
```

for password hashing.

Sensitive credentials are loaded from environment variables rather than being stored in the Git repository.

Required environment variables include:

```text
HAWK_ADMIN_PASSWORD
HAWK_CHALLENGE_SECRET
```

These values must never be committed to GitHub.

## Configuration

The project uses a JSON-based configuration system.

A sanitized configuration template is provided as:

```text
config.example.json
```

The local runtime configuration file should remain outside version control.

## Testing

The current automated test suite contains:

```text
Ran 13 tests
OK
```

The local lab has also been used to test controls including:

```text
HTTP 200  -> Allowed request
HTTP 403  -> Security block
HTTP 405  -> Method not allowed
HTTP 413  -> Request too large
HTTP 421  -> Unknown website
HTTP 429  -> Rate limit exceeded
HTTP 401  -> Authentication required
```

Additional validation has included:

- SQL injection detection
- XSS detection
- Path traversal detection
- Command injection detection
- Suspicious file access detection
- Bot detection
- Browser challenges
- Security headers
- Request IDs
- Protected dashboard APIs

## Technology Stack

```text
Python
Flask
Requests
Linux
JSON
Reverse Proxy
Web Application Security
HTTP Security
Rate Limiting
Bot Detection
Security Logging
```

## Project Structure

```text
HAWK-WAF/
├── app.py
├── config.example.json
├── requirements.txt
├── waf/
│   ├── __init__.py
│   ├── config.py
│   ├── detector.py
│   ├── logger.py
│   ├── proxy.py
│   ├── rate_limit.py
│   ├── challenge.py
│   ├── bot_detector.py
│   ├── admin.py
│   └── website_registry.py
├── dashboard/
│   ├── __init__.py
│   ├── app.py
│   └── templates/
│       ├── dashboard.html
│       ├── admin.html
│       └── admin_panel.html
├── rules/
│   └── rules.json
├── challenge/
│   └── challenge.html
├── tests/
│   ├── test_detector.py
│   └── test_rate_limit.py
└── README.md
```

## Current Local Deployment

The project has been developed and tested in a local authorized lab using:

```text
Backend   : 127.0.0.1:5001
HAWK WAF  : 127.0.0.1:8080
Dashboard : 127.0.0.1:9000
```

## Security Scope

HAWK WAF is intended for:

- Authorized security testing
- Local cybersecurity laboratories
- Defensive WAF development
- Web application security research
- Educational security projects

Do not deploy or use the system against applications or infrastructure without appropriate authorization.

## Future Development

Planned or possible future improvements include:

- Multi-user administration
- Multi-tenant architecture
- Role-Based Access Control (RBAC)
- Per-user API keys
- Database-backed configuration
- Expanded integration testing
- Production TLS deployment
- Advanced bot verification
- Additional WAF rule families
- Production deployment architecture
- Improved monitoring and alerting

## Project Purpose

HAWK WAF was developed as a hands-on cybersecurity engineering project to explore:

```text
Web Application Security
WAF Design
Reverse Proxy Architecture
HTTP Request Inspection
Attack Detection
Rate Limiting
Bot Detection
Authentication Security
Security Logging
Security Monitoring
```

## Author

Developed as an independent cybersecurity project and practical security engineering laboratory.

