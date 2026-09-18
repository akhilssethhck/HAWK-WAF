from waf.rate_limit import RateLimiter


limiter = RateLimiter(
    max_requests=3,
    window_seconds=10
)


ip = "127.0.0.1"


for number in range(1, 6):

    allowed = limiter.is_allowed(ip)

    print(
        f"Request {number}:",
        "ALLOW" if allowed else "BLOCK"
    )
