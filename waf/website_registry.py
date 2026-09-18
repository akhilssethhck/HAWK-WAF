import ipaddress
import socket
from urllib.parse import urlparse


class WebsiteRegistry:

    def __init__(self, config):
        self.config = config

    # ============================================================
    # CONFIGURATION
    # ============================================================

    def _websites(self):
        websites = self.config.get_section(
            "websites"
        )

        if not isinstance(websites, dict):
            return {}

        return websites

    def reload_config(self):
        self.config.reload()

    # ============================================================
    # NORMALIZATION
    # ============================================================

    @staticmethod
    def _normalize_host(host):

        if not host:
            return ""

        host = str(host).strip().lower()

        if host.startswith("[") and "]" in host:
            host = host[
                1:host.find("]")
            ]

        if ":" in host:

            parts = host.rsplit(":", 1)

            if (
                len(parts) == 2
                and parts[1].isdigit()
            ):
                host = parts[0]

        return host.rstrip(".")

    @classmethod
    def _normalize_domain(cls, domain):
        return cls._normalize_host(
            domain
        )

    # ============================================================
    # ORIGIN SECURITY CONFIG
    # ============================================================

    def _origin_security_config(self):

        settings = self.config.get_section(
            "origin_security"
        )

        if not isinstance(
            settings,
            dict
        ):
            settings = {}

        allowed_schemes = settings.get(
            "allowed_schemes",
            [
                "http",
                "https"
            ]
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

            "allowed_schemes":
                allowed_schemes
        }

    # ============================================================
    # IP SECURITY
    # ============================================================

    @staticmethod
    def _is_metadata_ip(ip):

        try:
            address = ipaddress.ip_address(
                ip
            )

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

    @staticmethod
    def _is_private_or_restricted_ip(ip):

        try:
            address = ipaddress.ip_address(
                ip
            )

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

    @staticmethod
    def _resolve_hostname(
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

    # ============================================================
    # ORIGIN VALIDATION
    # ============================================================

    def validate_website_origin(
        self,
        origin
    ):

        if not isinstance(
            origin,
            str
        ):
            return False

        origin = origin.strip()

        if not origin:
            return False

        security = (
            self._origin_security_config()
        )

        try:

            parsed = urlparse(
                origin
            )

            if (
                parsed.scheme.lower()
                not in security[
                    "allowed_schemes"
                ]
            ):
                return False

            if not parsed.hostname:
                return False

            if (
                parsed.username
                or parsed.password
            ):
                return False

            if parsed.path not in (
                "",
                "/"
            ):
                return False

            if parsed.params:
                return False

            if (
                parsed.query
                or parsed.fragment
            ):
                return False

            port = parsed.port

            if port is None:

                if (
                    parsed.scheme.lower()
                    == "https"
                ):
                    port = 443

                else:
                    port = 80

            if (
                port < 1
                or port > 65535
            ):
                return False

        except (
            ValueError,
            TypeError
        ):
            return False

        if not security["enabled"]:
            return True

        hostname = parsed.hostname

        # --------------------------------------------------------
        # Direct IP origin
        # --------------------------------------------------------

        try:

            ip = ipaddress.ip_address(
                hostname
            )

            if (
                security[
                    "block_metadata_ips"
                ]
                and self._is_metadata_ip(
                    str(ip)
                )
            ):
                return False

            if (
                not security[
                    "allow_private_origins"
                ]
                and self._is_private_or_restricted_ip(
                    str(ip)
                )
            ):
                return False

            return True

        except ValueError:
            pass

        # --------------------------------------------------------
        # DNS hostname origin
        # --------------------------------------------------------

        addresses = (
            self._resolve_hostname(
                hostname,
                port
            )
        )

        if not addresses:
            return False

        for address in addresses:

            if (
                security[
                    "block_metadata_ips"
                ]
                and self._is_metadata_ip(
                    address
                )
            ):
                return False

            if (
                not security[
                    "allow_private_origins"
                ]
                and self._is_private_or_restricted_ip(
                    address
                )
            ):
                return False

        return True

    # ============================================================
    # SITE LOOKUP
    # ============================================================

    def get_site(
        self,
        domain
    ):

        normalized_domain = (
            self._normalize_domain(
                domain
            )
        )

        if not normalized_domain:
            return None

        websites = self._websites()

        for (
            configured_domain,
            site_config
        ) in websites.items():

            if (
                self._normalize_domain(
                    configured_domain
                )
                == normalized_domain
            ):

                if not isinstance(
                    site_config,
                    dict
                ):
                    return None

                site_config = dict(
                    site_config
                )

                site_config[
                    "domain"
                ] = configured_domain

                return site_config

        return None

    # ============================================================
    # ORIGIN RESOLUTION
    # ============================================================

    def resolve_origin(
        self,
        domain
    ):

        site = self.get_site(
            domain
        )

        if not site:
            return None

        if not bool(
            site.get(
                "enabled",
                True
            )
        ):
            return None

        origin = site.get(
            "origin"
        )

        if not self.validate_website_origin(
            origin
        ):
            return None

        return origin.rstrip("/")

    # ============================================================
    # POLICY NORMALIZATION
    # ============================================================

    @staticmethod
    def normalize_policy(
        site_config
    ):

        if not isinstance(
            site_config,
            dict
        ):
            site_config = {}

        # --------------------------------------------------------
        # Rate limiting
        # --------------------------------------------------------

        rate_limit = site_config.get(
            "rate_limit",
            {}
        )

        if not isinstance(
            rate_limit,
            dict
        ):
            rate_limit = {}

        rate_policy = {
            "enabled": bool(
                rate_limit.get(
                    "enabled",
                    True
                )
            ),
            "max_requests": max(
                1,
                int(
                    rate_limit.get(
                        "max_requests",
                        20
                    )
                )
            ),
            "window_seconds": max(
                1,
                int(
                    rate_limit.get(
                        "window_seconds",
                        10
                    )
                )
            )
        }

        # --------------------------------------------------------
        # Bot protection
        # --------------------------------------------------------

        bot_protection = site_config.get(
            "bot_protection",
            {}
        )

        if not isinstance(
            bot_protection,
            dict
        ):
            bot_protection = {}

        bot_mode = str(
            bot_protection.get(
                "mode",
                "challenge"
            )
        ).strip().lower()

        if bot_mode not in (
            "block",
            "challenge",
            "log"
        ):
            bot_mode = "challenge"

        bot_policy = {
            "enabled": bool(
                bot_protection.get(
                    "enabled",
                    True
                )
            ),
            "mode": bot_mode,
            "request_window": max(
                1,
                int(
                    bot_protection.get(
                        "request_window",
                        10
                    )
                )
            ),
            "max_requests": max(
                1,
                int(
                    bot_protection.get(
                        "max_requests",
                        30
                    )
                )
            )
        }

        # --------------------------------------------------------
        # Browser verification
        # --------------------------------------------------------

        browser_verification = (
            site_config.get(
                "browser_verification",
                {}
            )
        )

        if not isinstance(
            browser_verification,
            dict
        ):
            browser_verification = {}

        browser_mode = str(
            browser_verification.get(
                "mode",
                "suspicious"
            )
        ).strip().lower()

        if browser_mode not in (
            "always",
            "suspicious"
        ):
            browser_mode = "suspicious"

        browser_policy = {
            "enabled": bool(
                browser_verification.get(
                    "enabled",
                    False
                )
            ),
            "mode": browser_mode,
            "token_lifetime": max(
                1,
                int(
                    browser_verification.get(
                        "token_lifetime",
                        300
                    )
                )
            )
        }

        # --------------------------------------------------------
        # WAF rules
        # --------------------------------------------------------

        waf_rules = site_config.get(
            "waf_rules",
            {}
        )

        if not isinstance(
            waf_rules,
            dict
        ):
            waf_rules = {}

        normalized_rules = {}

        for (
            rule_name,
            rule_config
        ) in waf_rules.items():

            if isinstance(
                rule_config,
                dict
            ):

                normalized_rules[
                    str(rule_name)
                ] = {
                    "enabled": bool(
                        rule_config.get(
                            "enabled",
                            True
                        )
                    )
                }

        # --------------------------------------------------------
        # Security headers
        # --------------------------------------------------------

        security_headers = site_config.get(
            "security_headers",
            {}
        )

        if not isinstance(
            security_headers,
            dict
        ):
            security_headers = {}

        security_headers_policy = {
            "enabled": bool(
                security_headers.get(
                    "enabled",
                    True
                )
            ),
            "x_content_type_options": str(
                security_headers.get(
                    "x_content_type_options",
                    "nosniff"
                )
            ),
            "x_frame_options": str(
                security_headers.get(
                    "x_frame_options",
                    "DENY"
                )
            ),
            "referrer_policy": str(
                security_headers.get(
                    "referrer_policy",
                    "strict-origin-when-cross-origin"
                )
            ),
            "permissions_policy": str(
                security_headers.get(
                    "permissions_policy",
                    "camera=(), microphone=(), geolocation=()"
                )
            ),
            "strict_transport_security": str(
                security_headers.get(
                    "strict_transport_security",
                    ""
                )
            )
        }

        # --------------------------------------------------------
        # Request security
        # --------------------------------------------------------

        request_security = (
            site_config.get(
                "request_security",
                {}
            )
        )

        if not isinstance(
            request_security,
            dict
        ):
            request_security = {}

        default_methods = [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
            "HEAD"
        ]

        allowed_methods = (
            request_security.get(
                "allowed_methods",
                default_methods
            )
        )

        if not isinstance(
            allowed_methods,
            list
        ):
            allowed_methods = (
                default_methods
            )

        normalized_methods = []

        for method in allowed_methods:

            method = str(
                method
            ).strip().upper()

            if (
                method
                and method
                not in normalized_methods
            ):
                normalized_methods.append(
                    method
                )

        if not normalized_methods:
            normalized_methods = (
                default_methods
            )

        request_security_policy = {
            "max_body_size": max(
                1,
                int(
                    request_security.get(
                        "max_body_size",
                        1048576
                    )
                )
            ),
            "allowed_methods":
                normalized_methods,
            "upstream_timeout": max(
                1,
                int(
                    request_security.get(
                        "upstream_timeout",
                        10
                    )
                )
            )
        }

        return {
            "rate_limit":
                rate_policy,

            "bot_protection":
                bot_policy,

            "browser_verification":
                browser_policy,

            "waf_rules":
                normalized_rules,

            "security_headers":
                security_headers_policy,

            "request_security":
                request_security_policy
        }

    # ============================================================
    # POLICY RESOLUTION
    # ============================================================

    def resolve_policy(
        self,
        domain
    ):

        site = self.get_site(
            domain
        )

        if not site:
            return None

        if not bool(
            site.get(
                "enabled",
                True
            )
        ):
            return None

        return self.normalize_policy(
            site
        )

    # ============================================================
    # LIST SITES
    # ============================================================

    def list_sites(self):

        websites = self._websites()

        results = []

        for (
            domain,
            site_config
        ) in websites.items():

            if not isinstance(
                site_config,
                dict
            ):
                continue

            results.append({
                "domain": domain,

                "origin":
                    site_config.get(
                        "origin"
                    ),

                "enabled": bool(
                    site_config.get(
                        "enabled",
                        True
                    )
                ),

                "policy":
                    self.normalize_policy(
                        site_config
                    )
            })

        return results
