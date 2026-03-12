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
    def __init__(self, db_path: Path, tlds: list[str]) -> None:
        self.log = logging.getLogger("Dynette")
        self.db_path = db_path
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

        if current_version == 0:
            self.log.info("Creating database...")
            columns = [
                "name text not null unique",
                "key blob not null",
                "password text",
                "last_query int default 0"
            ]
            query = f"create table domains({", ".join(columns)})"
            cur.execute(query)
            query = "pragma user_version = 2"
            cur.execute(query)
            current_version = 2

        if current_version == 1:
            self.log.info("Updating database schema...")
            query = "alter table domains add column last_query int default 0"
            cur.execute(query)
            query = "pragma user_version = 2"
            cur.execute(query)
            current_version = 2

        cur.close()
        self.db.commit()

    def commit(self) -> None:
        self.db.commit()

    def _get(self, domain: str) -> tuple[bytes, str | None] | None:
        query = "select key, password from domains where name = ?"
        cur = self.db.execute(query, (domain,))
        assert isinstance(cur, sqlite3.Cursor)
        result = cur.fetchone()
        cur.close()
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
            raise ValueError(
                f"This domain is not handled by this dynette server: {domain}."
            )

    def available(self, domain: str) -> bool:
        return self._get(domain) is None

    def register(
        self, domain: str, key: bytes | str, pwd: str | None, commit: bool = True
    ) -> None:
        self.log.info("Registering %s", domain)
        query = "insert into domains values(?, ?, ?)"
        key = key.encode() if isinstance(key, str) else key
        try:
            self.db.execute(query, (domain, key, pwd)).close()
        except sqlite3.IntegrityError:
            raise ForbiddenError(f"Domain {domain} is already registered") from None
        finally:
            if commit:
                self.db.commit()
        if pwd is not None:
            self.set_password(domain, b"", pwd, check=False, commit=False)

    def set_password(
        self,
        domain: str,
        key: bytes | str,
        pwd: str,
        check: bool = True,
        is_hashed: bool = False,
        commit: bool = True,
    ) -> None:
        self.log.debug("Setting password %s for %s", pwd, domain)
        key = key.encode() if isinstance(key, str) else key
        if 8 > len(pwd) > 1024:
            raise ValueError("Password should be between 8 and 1024 long")
        if check:
            self._check_key(domain, key)
        hashed = (
            pwd
            if is_hashed
            else bcrypt.hashpw(password=pwd.encode(), salt=bcrypt.gensalt(14)).decode()
        )
        try:
            query = "update domains set password = ? where name = ?"
            cur = self.db.execute(query, (hashed, domain))
            cur.close()
            if cur.rowcount == 0:
                raise ValueError(f"Can't update password for non-existing domain {domain}")
        finally:
            if commit:
                self.db.commit()

    def delete(self, domain: str, key: bytes | str | None, pwd: str | None) -> None:
        self.log.info("Deleting %s", domain)
        key = key.encode() if isinstance(key, str) else key
        if key:
            self._check_key(domain, key)
        elif pwd:
            self._check_pwd(domain, pwd)
        else:
            # Shouldnt happen, this is checked before
            raise ForbiddenError(f"No key or password passed for {domain}")

        try:
            query = "delete from domains where name = ?"
            self.db.execute(query, (domain,)).close()
        finally:
            self.db.commit()

    def set_last_query(self, domain: str, epoch: int, commit: bool = True) -> bool:
        try:
            query = "update domains set last_query = ? where name = ?"
            cur = self.db.execute(query, (epoch, domain))
            cur.close()
        finally:
            if commit:
                self.db.commit()
        return cur.rowcount != 0

    def iter(self, tld: str | None = None) -> Generator[tuple[str, bytes, str | None]]:
        tldwhere = f"where name like '%.{tld}'" if tld else ""
        query = f"select name, key, password from domains {tldwhere} order by name"
        cur = self.db.execute(query)
        yield from cur
        cur.close()
