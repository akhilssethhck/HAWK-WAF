import json
from pathlib import Path


class HAWKConfig:

    def __init__(
        self,
        config_file="config.json"
    ):

        self.config_file = Path(
            config_file
        )

        self.config = {}

        self.load()


    def load(self):

        try:

            with open(
                self.config_file,
                "r",
                encoding="utf-8"
            ) as file:

                self.config = json.load(file)

            print(
                "[+] HAWK WAF configuration loaded"
            )

            return self.config

        except FileNotFoundError:

            print(
                "[!] HAWK configuration file "
                "not found"
            )

            self.config = {}

            return {}

        except json.JSONDecodeError as error:

            print(
                "[!] Invalid HAWK configuration:"
            )

            print(error)

            self.config = {}

            return {}

        except Exception as error:

            print(
                "[!] Failed to load HAWK "
                "configuration:"
            )

            print(error)

            self.config = {}

            return {}


    def get(
        self,
        section,
        key,
        default=None
    ):

        return (
            self.config
            .get(section, {})
            .get(key, default)
        )


    def get_section(
        self,
        section
    ):

        return self.config.get(
            section,
            {}
        )


    def reload(self):

        print(
            "[*] Reloading HAWK configuration..."
        )

        return self.load()
