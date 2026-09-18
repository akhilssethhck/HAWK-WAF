import time
from collections import defaultdict, deque


class RateLimiter:
    """
    In-memory per-IP rate limiter.

    Default:
        20 requests
        per 10 seconds

    Per-request limits can be supplied to is_allowed()
    and get_remaining().
    """

    def __init__(
        self,
        max_requests=20,
        window_seconds=10
    ):

        self.max_requests = max(
            1,
            int(max_requests)
        )

        self.window_seconds = max(
            1,
            int(window_seconds)
        )

        self.requests = defaultdict(
            deque
        )

    # ========================================================
    # INTERNAL CLEANUP
    # ========================================================

    def _cleanup(
        self,
        ip,
        window_seconds
    ):

        current_time = time.time()

        request_times = self.requests[ip]

        while request_times:

            oldest = request_times[0]

            if (
                current_time - oldest
                > window_seconds
            ):
                request_times.popleft()

            else:
                break

        return request_times

    # ========================================================
    # RATE LIMIT CHECK
    # ========================================================

    def is_allowed(
        self,
        ip,
        max_requests=None,
        window_seconds=None
    ):

        if max_requests is None:
            max_requests = self.max_requests

        if window_seconds is None:
            window_seconds = self.window_seconds

        max_requests = max(
            1,
            int(max_requests)
        )

        window_seconds = max(
            1,
            int(window_seconds)
        )

        request_times = self._cleanup(
            ip,
            window_seconds
        )

        # Check limit before recording
        if len(request_times) >= max_requests:

            return False

        # Record current request
        request_times.append(
            time.time()
        )

        return True

    # ========================================================
    # REMAINING REQUESTS
    # ========================================================

    def get_remaining(
        self,
        ip,
        max_requests=None,
        window_seconds=None
    ):

        if max_requests is None:
            max_requests = self.max_requests

        if window_seconds is None:
            window_seconds = self.window_seconds

        max_requests = max(
            1,
            int(max_requests)
        )

        window_seconds = max(
            1,
            int(window_seconds)
        )

        request_times = self._cleanup(
            ip,
            window_seconds
        )

        remaining = (
            max_requests
            - len(request_times)
        )

        return max(
            0,
            remaining
        )

    # ========================================================
    # RESET IP
    # ========================================================

    def reset_ip(self, ip):

        if ip in self.requests:

            del self.requests[ip]
