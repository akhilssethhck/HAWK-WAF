import unittest

from waf.detector import WAFDetector


class TestHAWKDetector(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.detector = WAFDetector(
            "rules/rules.json"
        )

    def test_normal_request_is_allowed(self):

        result = self.detector.detect(
            "GET /search?q=hello"
        )

        self.assertFalse(
            result.blocked
        )

    def test_xss_is_blocked(self):

        result = self.detector.detect(
            "GET /search?q=<script>alert(1)</script>"
        )

        self.assertTrue(
            result.blocked
        )

        self.assertEqual(
            result.rule,
            "XSS"
        )

        self.assertEqual(
            result.severity,
            "HIGH"
        )

        self.assertIsNotNone(
            result.matched_pattern
        )

    def test_sql_injection_is_blocked(self):

        result = self.detector.detect(
            "GET /search?q=UNION SELECT username FROM users"
        )

        self.assertTrue(
            result.blocked
        )

        self.assertEqual(
            result.rule,
            "SQL_INJECTION"
        )

    def test_path_traversal_is_blocked(self):

        result = self.detector.detect(
            "GET /download?file=../../etc/passwd"
        )

        self.assertTrue(
            result.blocked
        )

        self.assertEqual(
            result.rule,
            "PATH_TRAVERSAL"
        )

    def test_command_injection_is_blocked(self):

        result = self.detector.detect(
            "GET /search?q=test;whoami"
        )

        self.assertTrue(
            result.blocked
        )

        self.assertEqual(
            result.rule,
            "COMMAND_INJECTION"
        )

    def test_file_access_is_blocked(self):

        result = self.detector.detect(
            "GET /download?file=/etc/passwd"
        )

        self.assertTrue(
            result.blocked
        )

        self.assertEqual(
            result.rule,
            "SUSPICIOUS_FILE_ACCESS"
        )

    def test_encoded_xss_is_blocked(self):

        result = self.detector.detect(
            "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E"
        )

        self.assertTrue(
            result.blocked
        )

        self.assertEqual(
            result.rule,
            "XSS"
        )

    def test_encoded_path_traversal_is_blocked(self):

        result = self.detector.detect(
            "GET /download?file=%2e%2e%2fetc%2fpasswd"
        )

        self.assertTrue(
            result.blocked
        )

        self.assertEqual(
            result.rule,
            "PATH_TRAVERSAL"
        )


if __name__ == "__main__":

    unittest.main()
