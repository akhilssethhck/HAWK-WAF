import base64
import hashlib
import hmac
import json
import secrets
import time


class HAWKChallenge:

    def __init__(
        self,
        secret=None,
        token_lifetime=300
    ):
        self.secret = (
            secret
            or secrets.token_hex(32)
        )

        self.token_lifetime = (
            token_lifetime
        )


    # =====================================
    # CREATE CHALLENGE
    # =====================================

    def create_challenge(
        self,
        redirect="/"
    ):

        nonce = secrets.token_hex(16)

        challenge = {

            "nonce": nonce,

            "created": int(
                time.time()
            ),

            "redirect": redirect

        }

        return challenge


    # =====================================
    # CREATE TOKEN
    # =====================================

    def create_token(
        self,
        challenge
    ):

        payload = json.dumps(
            challenge,
            separators=(",", ":")
        ).encode()


        encoded_payload = (
            base64.urlsafe_b64encode(
                payload
            )
            .decode()
            .rstrip("=")
        )


        signature = hmac.new(

            self.secret.encode(),

            encoded_payload.encode(),

            hashlib.sha256

        ).digest()


        encoded_signature = (
            base64.urlsafe_b64encode(
                signature
            )
            .decode()
            .rstrip("=")
        )


        return (
            encoded_payload
            + "."
            + encoded_signature
        )


    # =====================================
    # VERIFY TOKEN
    # =====================================

    def verify_token(
        self,
        token
    ):

        if not token:
            return False


        try:

            parts = token.split(
                "."
            )


            if len(parts) != 2:
                return False


            encoded_payload = parts[0]

            provided_signature = parts[1]


            expected_signature = (
                hmac.new(

                    self.secret.encode(),

                    encoded_payload.encode(),

                    hashlib.sha256

                ).digest()
            )


            expected_encoded = (
                base64.urlsafe_b64encode(
                    expected_signature
                )
                .decode()
                .rstrip("=")
            )


            if not hmac.compare_digest(

                provided_signature,

                expected_encoded

            ):

                return False


            padding = (
                "="
                * (
                    (4 - len(encoded_payload) % 4)
                    % 4
                )
            )


            payload = base64.urlsafe_b64decode(

                encoded_payload
                + padding

            )


            challenge = json.loads(
                payload.decode()
            )


            created = int(
                challenge.get(
                    "created",
                    0
                )
            )


            current_time = int(
                time.time()
            )


            age = (
                current_time
                - created
            )


            if age < 0:
                return False


            if age > self.token_lifetime:
                return False


            if not challenge.get(
                "nonce"
            ):
                return False


            redirect = challenge.get(
                "redirect",
                "/"
            )


            if not isinstance(
                redirect,
                str
            ):

                return False


            if not redirect.startswith(
                "/"
            ):

                return False


            return challenge


        except (
            ValueError,
            TypeError,
            json.JSONDecodeError,
            UnicodeDecodeError
        ):

            return False

        except Exception:

            return False
