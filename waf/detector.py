import json
import re
from pathlib import Path
from urllib.parse import unquote


class DetectionResult:

    def __init__(
        self,
        blocked=False,
        rule=None,
        severity="LOW",
        matched_pattern=None
    ):
        self.blocked = blocked
        self.rule = rule
        self.severity = severity
        self.matched_pattern = matched_pattern


class WAFDetector:

    def __init__(self, rules_file="rules/rules.json"):

        self.rules_file = Path(rules_file)

        self.rules = {}

        self.rules_mtime = None

        self.load_rules()

    # ========================================================
    # LOAD RULES
    # ========================================================

    def load_rules(self):

        try:

            with open(
                self.rules_file,
                "r",
                encoding="utf-8"
            ) as file:

                rules = json.load(file)

            self.rules = rules

            self.rules_mtime = (
                self.rules_file.stat().st_mtime
            )

            print(
                f"[+] Loaded {len(rules)} HAWK WAF rules"
            )

            return rules

        except FileNotFoundError:

            print(
                f"[!] Rules file not found: "
                f"{self.rules_file}"
            )

            self.rules = {}

            return {}

        except json.JSONDecodeError as error:

            print(
                f"[!] Invalid JSON in rules file: "
                f"{error}"
            )

            self.rules = {}

            return {}

        except Exception as error:

            print(
                f"[!] Failed to load rules: "
                f"{error}"
            )

            self.rules = {}

            return {}

    # ========================================================
    # RULE RELOAD
    # ========================================================

    def check_for_rule_changes(self):

        try:

            current_mtime = (
                self.rules_file.stat().st_mtime
            )

            if self.rules_mtime is None:

                self.load_rules()

                return

            if current_mtime != self.rules_mtime:

                print(
                    "[*] rules.json changed"
                )

                print(
                    "[*] Reloading HAWK WAF rules..."
                )

                self.load_rules()

                print(
                    "[+] HAWK WAF rules reloaded successfully"
                )

        except FileNotFoundError:

            print(
                f"[!] Rules file not found: "
                f"{self.rules_file}"
            )

        except Exception as error:

            print(
                f"[!] Failed to check rule changes: "
                f"{error}"
            )

    # ========================================================
    # NORMALIZATION
    # ========================================================

    def normalize(self, value):

        if not value:

            return ""

        value = str(value)

        for _ in range(3):

            decoded = unquote(value)

            if decoded == value:

                break

            value = decoded

        value = value.lower()

        value = re.sub(
            r"\s+",
            " ",
            value
        )

        return value

    # ========================================================
    # RULE ENABLED CHECK
    # ========================================================

    @staticmethod
    def is_rule_enabled(
        rule_name,
        rule_config,
        rule_overrides
    ):

        # Global rule state
        enabled = bool(
            rule_config.get(
                "enabled",
                True
            )
        )

        if not enabled:
            return False

        # No per-site override
        if not isinstance(
            rule_overrides,
            dict
        ):
            return True

        override = rule_overrides.get(
            rule_name
        )

        if not isinstance(
            override,
            dict
        ):
            return True

        # Per-site enabled/disabled state
        if "enabled" in override:

            return bool(
                override["enabled"]
            )

        return True

    # ========================================================
    # DETECTION
    # ========================================================

    def detect(
        self,
        request_data,
        rule_overrides=None
    ):

        self.check_for_rule_changes()

        normalized_data = (
            self.normalize(request_data)
        )

        if not normalized_data:

            return DetectionResult()

        if not isinstance(
            rule_overrides,
            dict
        ):
            rule_overrides = {}

        for rule_name, rule_config in (
            self.rules.items()
        ):

            if not isinstance(
                rule_config,
                dict
            ):
                continue

            # ------------------------------------------------
            # GLOBAL + PER-SITE ENABLE/DISABLE
            # ------------------------------------------------

            if not self.is_rule_enabled(
                rule_name,
                rule_config,
                rule_overrides
            ):
                continue

            severity = rule_config.get(
                "severity",
                "HIGH"
            )

            patterns = rule_config.get(
                "patterns",
                []
            )

            if not isinstance(
                patterns,
                list
            ):
                continue

            # ------------------------------------------------
            # MATCH PATTERNS
            # ------------------------------------------------

            for pattern in patterns:

                try:

                    if re.search(
                        pattern,
                        normalized_data,
                        re.IGNORECASE
                    ):

                        print(
                            f"[BLOCK] "
                            f"Rule={rule_name} "
                            f"Severity={severity}"
                        )

                        print(
                            f"[MATCH] "
                            f"Pattern={pattern}"
                        )

                        return DetectionResult(

                            blocked=True,

                            rule=rule_name,

                            severity=severity,

                            matched_pattern=pattern

                        )

                except re.error as error:

                    print(
                        f"[!] Invalid regex "
                        f"in rule "
                        f"{rule_name}: "
                        f"{error}"
                    )

        return DetectionResult(

            blocked=False,

            rule=None,

            severity="LOW",

            matched_pattern=None

        )

    # ========================================================
    # RELOAD
    # ========================================================

    def reload_rules(self):

        self.load_rules()

        print(
            "[+] HAWK WAF rules reloaded"
        )

    # ========================================================
    # INSPECT
    # ========================================================

    def inspect(
        self,
        request_data,
        rule_overrides=None
    ):

        return self.detect(
            request_data,
            rule_overrides=rule_overrides
        )
