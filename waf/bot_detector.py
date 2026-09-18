import time
from collections import defaultdict, deque


class HAWKBotDetector:

    def __init__(
        self,
        request_window=10,
        max_requests=30
    ):
        self.request_window = max(
            1,
            int(request_window)
        )

        self.max_requests = max(
            1,
            int(max_requests)
        )

        self.request_history = defaultdict(deque)

        self.suspicious_user_agents = [
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "zgrab",
            "gobuster",
            "dirbuster",
            "ffuf",
            "wfuzz",
            "burpsuite",
            "python-requests",
            "curl",
            "wget",
            "httpclient",
            "scrapy",
            "aiohttp",
            "libwww-perl"
        ]

        self.empty_user_agents = [
            "",
            "-"
        ]

    # =====================================
    # REQUEST HISTORY
    # =====================================

    def record_request(
        self,
        ip,
        request_window=None
    ):

        if request_window is None:
            request_window = self.request_window

        request_window = max(
            1,
            int(request_window)
        )

        now = time.time()

        history = self.request_history[ip]

        while history:

            if now - history[0] > request_window:
                history.popleft()

            else:
                break

        history.append(now)

    # =====================================
    # REQUEST FREQUENCY
    # =====================================

    def get_request_count(
        self,
        ip,
        request_window=None
    ):

        if request_window is None:
            request_window = self.request_window

        request_window = max(
            1,
            int(request_window)
        )

        now = time.time()

        history = self.request_history[ip]

        while history:

            if now - history[0] > request_window:
                history.popleft()

            else:
                break

        return len(history)

    # =====================================
    # USER AGENT CHECK
    # =====================================

    def check_user_agent(self, user_agent):

        if not user_agent:
            return True, "EMPTY_USER_AGENT"

        normalized = user_agent.lower().strip()

        if normalized in self.empty_user_agents:
            return True, "EMPTY_USER_AGENT"

        for signature in self.suspicious_user_agents:

            if signature in normalized:
                return True, "SUSPICIOUS_USER_AGENT"

        return False, None

    # =====================================
    # HEADER CHECK
    # =====================================

    def check_headers(self, headers):

        suspicious = 0

        if not headers.get("User-Agent"):
            suspicious += 1

        if not headers.get("Accept"):
            suspicious += 1

        if not headers.get("Accept-Language"):
            suspicious += 1

        if not headers.get("Accept-Encoding"):
            suspicious += 1

        if suspicious >= 3:
            return True, "ABNORMAL_HEADERS"

        return False, None

    # =====================================
    # PATH SCANNING CHECK
    # =====================================

    def check_path_behavior(self, path):

        suspicious_paths = [

            "/wp-admin",
            "/wp-login.php",
            "/phpmyadmin",
            "/admin",
            "/administrator",
            "/.env",
            "/.git",
            "/config.php",
            "/server-status",
            "/actuator",
            "/debug",
            "/console"

        ]

        normalized_path = path.lower()

        for suspicious_path in suspicious_paths:

            if normalized_path.startswith(
                suspicious_path
            ):
                return True, "SCANNER_PATH"

        return False, None

    # =====================================
    # REQUEST BURST CHECK
    # =====================================

    def check_request_rate(
        self,
        ip,
        request_window=None,
        max_requests=None
    ):

        if request_window is None:
            request_window = self.request_window

        if max_requests is None:
            max_requests = self.max_requests

        request_window = max(
            1,
            int(request_window)
        )

        max_requests = max(
            1,
            int(max_requests)
        )

        count = self.get_request_count(
            ip,
            request_window=request_window
        )

        if count > max_requests:
            return True, "HIGH_REQUEST_RATE"

        return False, None

    # =====================================
    # MAIN ANALYSIS
    # =====================================

    def analyze(
        self,
        ip,
        user_agent,
        headers,
        path,
        request_window=None,
        max_requests=None
    ):

        if request_window is None:
            request_window = self.request_window

        if max_requests is None:
            max_requests = self.max_requests

        request_window = max(
            1,
            int(request_window)
        )

        max_requests = max(
            1,
            int(max_requests)
        )

        self.record_request(
            ip,
            request_window=request_window
        )

        reasons = []

        suspicious, reason = self.check_user_agent(
            user_agent
        )

        if suspicious:
            reasons.append(reason)

        suspicious, reason = self.check_headers(
            headers
        )

        if suspicious:
            reasons.append(reason)

        suspicious, reason = self.check_path_behavior(
            path
        )

        if suspicious:
            reasons.append(reason)

        suspicious, reason = self.check_request_rate(
            ip,
            request_window=request_window,
            max_requests=max_requests
        )

        if suspicious:
            reasons.append(reason)

        risk_score = 0

        if "EMPTY_USER_AGENT" in reasons:
            risk_score += 40

        if "SUSPICIOUS_USER_AGENT" in reasons:
            risk_score += 70

        if "ABNORMAL_HEADERS" in reasons:
            risk_score += 30

        if "SCANNER_PATH" in reasons:
            risk_score += 40

        if "HIGH_REQUEST_RATE" in reasons:
            risk_score += 50

        if risk_score >= 70:
            decision = "BLOCK"

        elif risk_score >= 40:
            decision = "CHALLENGE"

        else:
            decision = "ALLOW"

        return {
            "is_bot": risk_score >= 40,
            "risk_score": risk_score,
            "decision": decision,
            "reasons": reasons,
            "request_count": self.get_request_count(
                ip,
                request_window=request_window
            )
        }
