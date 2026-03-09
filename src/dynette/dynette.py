import hmac
import logging
import re
import sqlite3
from collections.abc import Generator
from pathlib import Path

import bcrypt

DOMAIN_REGEX = re.compile(
    r"^([a-z0-9]{1}([a-z0-9\-]*[a-z0-9])*)(\.[a-z0-9]{1}([a-z0-9\-]*[a-z0-9])*)*(\.[a-z]{1}([a-z0-9\-]*[a-z0-9])*)$"
)


class ForbiddenError(Exception):
    """Invalid key or password."""


class Dynette:
    def __init__(self, db_folder: Path, tlds: list[str]) -> None:
        self.log = logging.getLogger("Dynette")
        self.db_folder = db_folder
        self.db_path = self.db_folder / "domains.sql"
        self.tlds = tlds
        self.log.debug(
            "Initializing Dynette at %s for domains: %s", self.db_path, ", ".join(tlds)
        )
        self.db = sqlite3.connect(self.db_path)
        self._initialize()

    def _initialize(self) -> None:
        cur = self.db.cursor()
        query = "pragma user_version"
        current_version = next(cur.execute(query))[0]
        if current_version == 1:
            return
        schema = "name text not null unique, key blob not null, password text"
        query = f"create table domains({schema})"
        cur.execute(schema)
        query = "pragma user_version = 1"
        cur.execute(query)
        cur.close()
        self.db.commit()

    def _get(self, domain: str) -> tuple[bytes, str | None] | None:
        query = "select key, password from domains where name = ?"
        cur = self.db.execute(query, (domain,))
        assert isinstance(cur, sqlite3.Cursor)
        result = cur.fetchone()
        if result is None:
            return None
        return (result[0], result[1])

    def _check_key(self, domain: str, key: bytes) -> None:
        creds = self._get(domain)
        assert creds is not None
        realkey = creds[0]
        if not hmac.compare_digest(key, realkey):
            raise ForbiddenError(f"Invalid key for {domain}")

    def _check_pwd(self, domain: str, pwd: str) -> None:
        creds = self._get(domain)
        if creds is None:
            raise ValueError(f"Can't check password for non-existing domain {domain}")
        assert creds is not None
        realpwd = creds[1]
        if realpwd is None:
            raise ForbiddenError(f"Password passed but no password set for {domain}")
        if not bcrypt.checkpw(pwd.encode(), realpwd.encode()):
            raise ForbiddenError(f"Invalid password for {domain}")

    def validate(self, domain: str) -> None:
        if not isinstance(domain, str):
            raise TypeError(f"Domain is not a string: {domain}")
        if not DOMAIN_REGEX.match(domain):
            raise ValueError(f"This is not a valid domain: {domain}")
        if len(domain.split(".")) != 3 or domain.split(".", 1)[-1] not in self.tlds:
            raise ValueError("This subdomain is not handled by this dynette server.")

    def available(self, domain: str) -> bool:
        return self._get(domain) is None

    def register(self, domain: str, key: bytes | str, pwd: str | None) -> None:
        query = "insert into domains values(?, ?, ?)"
        key = key.encode() if isinstance(key, str) else key
        try:
            self.db.execute(query, (domain, key, pwd)).close()
        except sqlite3.IntegrityError:
            raise ForbiddenError(f"Domain {domain} is already registered") from None
        self.db.commit()
        if pwd is not None:
            self.set_password(domain, b"", pwd, check=False)

    def set_password(
        self, domain: str, key: bytes | str, pwd: str, check: bool = True
    ) -> None:
        key = key.encode() if isinstance(key, str) else key
        if 8 > len(pwd) > 1024:
            raise ValueError("Password should be between 8 and 1024 long")
        if check:
            self._check_key(domain, key)
        hashed = bcrypt.hashpw(password=pwd.encode(), salt=bcrypt.gensalt(14)).decode()
        query = "update domains set password = ? where name = ?"
        cur = self.db.execute(query, (hashed, domain))
        if cur.rowcount == 0:
            raise ValueError(f"Can't update password for non-existing domain {domain}")
        self.db.commit()

    def delete(self, domain: str, key: bytes | str | None, pwd: str | None) -> None:
        key = key.encode() if isinstance(key, str) else key
        if key:
            self._check_key(domain, key)
        elif pwd:
            self._check_pwd(domain, pwd)
        else:
            # Shouldnt happen, this is checked before
            raise ForbiddenError(f"No key or password passed for {domain}")

        query = "delete from domains where name = ?"
        self.db.execute(query, (domain,))

    def iter(self) -> Generator[tuple[str, bytes, str | None]]:
        query = "select name, key, password from domains order by name"
        yield from self.db.execute(query)
