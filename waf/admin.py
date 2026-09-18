import hashlib
import hmac
import secrets
import time
from collections import defaultdict


class HAWKAdmin:
    """
    HAWK WAF administrator authentication and
    session management.
    """

    def __init__(
        self,
        username="admin",
        password=None,
        password_hash=None,
        session_lifetime=3600
    ):

        self.username = username
        self.session_lifetime = int(session_lifetime)

        self.sessions = {}

        self.failed_attempts = defaultdict(list)

        # -------------------------------------------------
        # Password storage
        # -------------------------------------------------

        if password_hash:

            self.password_hash = password_hash

        elif password:

            self.password_hash = self.hash_password(
                password
            )

        else:

            temporary_password = secrets.token_urlsafe(24)

            self.password_hash = self.hash_password(
                temporary_password
            )

            print(
                "[!] No administrator password was supplied."
            )

            print(
                "[!] Temporary administrator password:"
            )

            print(
                temporary_password
            )

    # =====================================================
    # PASSWORD HASHING
    # =====================================================

    @staticmethod
    def hash_password(password):

        if not isinstance(password, str):

            raise TypeError(
                "Password must be a string"
            )

        salt = secrets.token_bytes(32)

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            120000
        )

        return (
            salt.hex()
            + ":"
            + password_hash.hex()
        )

    # =====================================================
    # PASSWORD VERIFICATION
    # =====================================================

    @staticmethod
    def verify_password(
        password,
        stored_hash
    ):

        try:

            if not isinstance(password, str):
                return False

            if not isinstance(stored_hash, str):
                return False

            parts = stored_hash.split(":", 1)

            if len(parts) != 2:
                return False

            salt_hex = parts[0]
            hash_hex = parts[1]

            salt = bytes.fromhex(
                salt_hex
            )

            expected_hash = bytes.fromhex(
                hash_hex
            )

            actual_hash = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                120000
            )

            return hmac.compare_digest(
                actual_hash,
                expected_hash
            )

        except Exception:

            return False

    # =====================================================
    # LOGIN RATE LIMIT
    # =====================================================

    def login_allowed(
        self,
        ip,
        max_attempts=5,
        window=300
    ):

        now = time.time()

        attempts = self.failed_attempts[ip]

        while attempts:

            if now - attempts[0] > window:

                attempts.pop(0)

            else:

                break

        return len(attempts) < max_attempts

    # =====================================================
    # RECORD FAILED LOGIN
    # =====================================================

    def record_failed_login(
        self,
        ip
    ):

        self.failed_attempts[ip].append(
            time.time()
        )

    # =====================================================
    # RESET FAILED ATTEMPTS
    # =====================================================

    def reset_failed_attempts(
        self,
        ip
    ):

        if ip in self.failed_attempts:

            del self.failed_attempts[ip]

    # =====================================================
    # AUTHENTICATE ADMIN
    # =====================================================

    def authenticate(
        self,
        username,
        password,
        ip
    ):

        # -------------------------------------------------
        # Login rate limit
        # -------------------------------------------------

        if not self.login_allowed(ip):

            print(
                f"[ADMIN] Login rate limit exceeded "
                f"for {ip}"
            )

            return None

        # -------------------------------------------------
        # Validate input
        # -------------------------------------------------

        if not isinstance(username, str):

            self.record_failed_login(ip)

            return None

        if not isinstance(password, str):

            self.record_failed_login(ip)

            return None

        # -------------------------------------------------
        # Username comparison
        # -------------------------------------------------

        username_match = hmac.compare_digest(
            username,
            self.username
        )

        # -------------------------------------------------
        # Password comparison
        # -------------------------------------------------

        password_match = self.verify_password(
            password,
            self.password_hash
        )

        # -------------------------------------------------
        # Authentication failed
        # -------------------------------------------------

        if not username_match or not password_match:

            self.record_failed_login(ip)

            print(
                f"[ADMIN] Failed login from {ip}"
            )

            return None

        # -------------------------------------------------
        # Successful authentication
        # -------------------------------------------------

        self.reset_failed_attempts(ip)

        session_token = secrets.token_urlsafe(48)

        self.sessions[session_token] = {

            "username": username,

            "created": time.time(),

            "ip": ip

        }

        print(
            f"[ADMIN] Successful login from {ip}"
        )

        return session_token

    # =====================================================
    # LOGIN COMPATIBILITY METHOD
    # =====================================================

    def login(
        self,
        username,
        password,
        ip
    ):

        return self.authenticate(
            username,
            password,
            ip
        )

    # =====================================================
    # VERIFY SESSION
    # =====================================================

    def verify_session(
        self,
        token,
        ip
    ):

        if not token:

            return False

        if not isinstance(token, str):

            return False

        session = self.sessions.get(token)

        if not session:

            return False

        # -------------------------------------------------
        # Session expiration
        # -------------------------------------------------

        now = time.time()

        session_age = (
            now
            - session["created"]
        )

        if session_age > self.session_lifetime:

            del self.sessions[token]

            return False

        # -------------------------------------------------
        # IP binding
        # -------------------------------------------------

        if session["ip"] != ip:

            return False

        return True

    # =====================================================
    # VALIDATE SESSION COMPATIBILITY METHOD
    # =====================================================

    def validate_session(
        self,
        token,
        ip=None
    ):

        if ip is None:

            session = self.sessions.get(token)

            if not session:

                return False

            ip = session.get("ip")

        return self.verify_session(
            token,
            ip
        )

    # =====================================================
    # GET SESSION INFORMATION
    # =====================================================

    def get_session(
        self,
        token
    ):

        if not token:

            return None

        session = self.sessions.get(token)

        if not session:

            return None

        if (
            time.time()
            - session["created"]
            > self.session_lifetime
        ):

            del self.sessions[token]

            return None

        return session.copy()

    # =====================================================
    # LOGOUT
    # =====================================================

    def logout(
        self,
        token
    ):

        if not token:

            return False

        if token in self.sessions:

            del self.sessions[token]

            print(
                "[ADMIN] Session logged out"
            )

            return True

        return False

    # =====================================================
    # CLEANUP EXPIRED SESSIONS
    # =====================================================

    def cleanup_sessions(self):

        now = time.time()

        expired_tokens = []

        for token, session in list(
            self.sessions.items()
        ):

            created = session.get(
                "created",
                now
            )

            if (
                now - created
                > self.session_lifetime
            ):

                expired_tokens.append(token)

        for token in expired_tokens:

            self.sessions.pop(
                token,
                None
            )

        return len(expired_tokens)

    # =====================================================
    # SESSION COUNT
    # =====================================================

    def session_count(self):

        self.cleanup_sessions()

        return len(self.sessions)
