from waf.detector import WAFDetector


waf = WAFDetector()


tests = [
    "hello world",
    "normal search request",
    "<script>alert(1)</script>",
    "UNION SELECT username,password",
    "../../etc/passwd",
    "hello; whoami"
]


for payload in tests:

    result = waf.inspect(payload)

    print("=" * 50)
    print("Input:", payload)
    print("Blocked:", result.blocked)
    print("Rule:", result.rule)
    print("Severity:", result.severity)
