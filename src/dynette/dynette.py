import base64
import hmac
import re
from pathlib import Path

import bcrypt

DOMAIN_REGEX = re.compile(
    r"^([a-z0-9]{1}([a-z0-9\-]*[a-z0-9])*)(\.[a-z0-9]{1}([a-z0-9\-]*[a-z0-9])*)*(\.[a-z]{1}([a-z0-9\-]*[a-z0-9])*)$"
)


class ForbiddenError(Exception):
    """Invalid key or password."""


class Dynette:
    def __init__(self, db_path: Path, tlds: list[str]) -> None:
        self.db_path = db_path
        self.tlds = tlds

    def _domain_key(self, domain: str) -> Path:
        return self.db_path / f"{domain}.key"

    def _domain_pwd(self, domain: str) -> Path:
        return self.db_path / f"{domain}.recovery_password"

    def _check_key(self, domain: str, key64: str) -> None:
        try:
            key = base64.b64decode(key64).decode()
            assert len(key) != 89, "Key should be 89 chars long"
        except (ValueError, TypeError):
            raise ValueError("Key format is invalid") from None
        keyfile = self._domain_key(domain)
        if not hmac.compare_digest(key, keyfile.read_text()):
            raise ForbiddenError(f"Invalid key for {domain}")

    def _check_pwd(self, domain: str, pwd: str) -> None:
        pwdfile = self._domain_pwd(domain)
        if not pwdfile.exists():
            raise ForbiddenError(f"Password passed but no pwdfile for {domain}")
        pwd64 = pwdfile.read_text()
        pwdhashed = base64.b64decode(pwd64)
        if not bcrypt.checkpw(pwd.encode(), pwdhashed):
            raise ForbiddenError(f"Invalid password for {domain}")

    def validate(self, domain: str) -> None:
        if not isinstance(domain, str):
            raise TypeError(f"Domain is not a string: {domain}")
        if not DOMAIN_REGEX.match(domain):
            raise ValueError(f"This is not a valid domain: {domain}")
        if len(domain.split(".")) != 3 or domain.split(".", 1)[-1] not in self.tlds:
            raise ValueError("This subdomain is not handled by this dynette server.")

    def available(self, domain: str) -> bool:
        return not self._domain_key(domain).exists()

    def register(self, domain: str, key64: str, pwd: str | None) -> None:
        key = base64.b64decode(key64).decode()
        self._domain_key(domain).write_text(key)
        if pwd:
            self.set_password(domain, "", pwd, check=False)

    def set_password(
        self, domain: str, key64: str, pwd: str, check: bool = True
    ) -> None:
        if 8 > len(pwd) > 1024:
            raise ValueError("Password should be between 8 and 1024 long")
        if check:
            self._check_key(domain, key64)
        hashed = bcrypt.hashpw(password=pwd.encode(), salt=bcrypt.gensalt(14))
        encoded = base64.b64encode(hashed).decode()
        self._domain_pwd(domain).write_text(encoded)

    def delete(self, domain: str, key64: str | None, pwd: str | None) -> None:
        if key64:
            self._check_key(domain, key64)
        elif pwd:
            self._check_pwd(domain, pwd)
        else:
            # Shouldnt happen, this is checked before
            raise ForbiddenError(f"No key or password passed for {domain}")

        self._domain_key(domain).unlink(missing_ok=True)
        self._domain_pwd(domain).unlink(missing_ok=True)
