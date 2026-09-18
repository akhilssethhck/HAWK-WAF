import unittest

from waf.rate_limit import RateLimiter


class TestHAWKRateLimiter(unittest.TestCase):

    def test_requests_are_allowed_under_limit(self):

        limiter = RateLimiter(
            max_requests=3,
            window_seconds=10
        )

        self.assertTrue(
            limiter.is_allowed("127.0.0.1")
        )

        self.assertTrue(
            limiter.is_allowed("127.0.0.1")
        )

        self.assertTrue(
            limiter.is_allowed("127.0.0.1")
        )

    def test_request_is_blocked_after_limit(self):

        limiter = RateLimiter(
            max_requests=3,
            window_seconds=10
        )

        for _ in range(3):

            self.assertTrue(
                limiter.is_allowed(
                    "127.0.0.1"
                )
            )

        self.assertFalse(
            limiter.is_allowed(
                "127.0.0.1"
            )
        )

    def test_different_ips_have_separate_limits(self):

        limiter = RateLimiter(
            max_requests=2,
            window_seconds=10
        )

        self.assertTrue(
            limiter.is_allowed(
                "192.168.1.10"
            )
        )

        self.assertTrue(
            limiter.is_allowed(
                "192.168.1.10"
            )
        )

        self.assertFalse(
            limiter.is_allowed(
                "192.168.1.10"
            )
        )

        self.assertTrue(
            limiter.is_allowed(
                "192.168.1.20"
            )
        )

    def test_remaining_requests(self):

        limiter = RateLimiter(
            max_requests=5,
            window_seconds=10
        )

        self.assertEqual(
            limiter.get_remaining(
                "127.0.0.1"
            ),
            5
        )

        limiter.is_allowed(
            "127.0.0.1"
        )

        self.assertEqual(
            limiter.get_remaining(
                "127.0.0.1"
            ),
            4
        )

    def test_reset_ip(self):

        limiter = RateLimiter(
            max_requests=2,
            window_seconds=10
        )

        limiter.is_allowed(
            "127.0.0.1"
        )

        limiter.is_allowed(
            "127.0.0.1"
        )

        self.assertFalse(
            limiter.is_allowed(
                "127.0.0.1"
            )
        )

        limiter.reset_ip(
            "127.0.0.1"
        )

        self.assertTrue(
            limiter.is_allowed(
                "127.0.0.1"
            )
        )


if __name__ == "__main__":

    unittest.main()
