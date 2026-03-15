import hmac
import logging
import re
from collections.abc import Generator
from pathlib import Path

import bcrypt
import sqlalchemy as sa
import sqlalchemy.exc
from sqlalchemy.orm import Mapped, Session, declarative_base, mapped_column

DOMAIN_REGEX = re.compile(
    r"^([a-z0-9]{1}([a-z0-9\-]*[a-z0-9])*)(\.[a-z0-9]{1}([a-z0-9\-]*[a-z0-9])*)*(\.[a-z]{1}([a-z0-9\-]*[a-z0-9])*)$"
)


class ForbiddenError(Exception):
    """Invalid key or password."""


Base = declarative_base()


class Domain(Base):
    __tablename__ = "domains"
    name: Mapped[str] = mapped_column(primary_key=True, unique=True)
    key: Mapped[bytes] = mapped_column(sa.BLOB, nullable=False)
    password: Mapped[str] = mapped_column(nullable=True, default=None)
    last_query: Mapped[int] = mapped_column(default=0)


class Dynette:
    def __init__(self, db_path: Path, tlds: list[str]) -> None:
        self.log = logging.getLogger("Dynette")
        self.db_path = db_path
        self.tlds = tlds

    def init(self) -> None:
        self.log.debug(
            "Initializing Dynette at %s for domains: %s",
            self.db_path,
            ", ".join(self.tlds),
        )
        self.db = sa.create_engine(f"sqlite:///{self.db_path.resolve()}")
        self.db_flag = self.db_path.parent / (self.db_path.name + ".flag")

        with self.db.connect() as conn:
            stmt = sa.text("pragma user_version")
            stmt_set_version = sa.text("pragma user_version = 2")
            current_version: int = conn.execute(stmt).scalar_one()
            self.log.debug("DB is at version %d", current_version)

            if current_version == 0:
                self.log.info("Creating database...")
                Base.metadata.create_all(self.db)
                conn.execute(stmt_set_version)

            if current_version == 1:
                self.log.info("Updating database schema...")
                stmt = sa.text(
                    "alter table domains add column last_query int default 0"
                )
                conn.execute(stmt)
                conn.execute(stmt_set_version)
            conn.commit()

    def _get(self, domain: str) -> Domain | None:
        with Session(self.db) as session:
            stmt = sa.select(Domain).where(Domain.name == domain)
            return session.execute(stmt).scalar_one_or_none()

    def _check_key(self, domain: str, key: bytes) -> None:
        creds = self._get(domain)
        if creds is None:
            raise ValueError(f"Can't check key for non-existing domain {domain}")
        if not hmac.compare_digest(key, creds.key):
            raise ForbiddenError(f"Invalid key for {domain}")

    def _check_pwd(self, domain: str, pwd: str) -> None:
        creds = self._get(domain)
        if creds is None:
            raise ValueError(f"Can't check password for non-existing domain {domain}")
        if creds.password is None:
            raise ForbiddenError(f"Password passed but no password set for {domain}")
        if not bcrypt.checkpw(pwd.encode(), creds.password.encode()):
            raise ForbiddenError(f"Invalid password for {domain}")

    def _hash_pwd(self, pwd: str) -> str:
        return bcrypt.hashpw(password=pwd.encode(), salt=bcrypt.gensalt(14)).decode()

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

    def register(self, domain: str, key: bytes | str, pwd: str | None) -> None:
        self.log.info("Registering %s", domain)
        key = key.encode() if isinstance(key, str) else key
        pwd = self._hash_pwd(pwd) if isinstance(pwd, str) else pwd
        try:
            with Session(self.db) as session:
                session.add(Domain(name=domain, key=key, password=pwd))
                session.commit()
        except sqlalchemy.exc.IntegrityError:
            raise ForbiddenError(f"Domain {domain} is already registered") from None
        self.db_flag.touch()

    def set_password(
        self, domain: str, key: bytes | str, pwd: str, migration: bool = False
    ) -> None:
        self.log.debug("Setting password %s for %s", pwd, domain)
        key = key.encode() if isinstance(key, str) else key
        if 8 > len(pwd) > 1024:
            raise ValueError("Password should be between 8 and 1024 long")
        if not migration:
            self._check_key(domain, key)
        hashed = pwd if migration else self._hash_pwd(pwd)
        with Session(self.db) as session:
            stmt = (
                sa.update(Domain).where(Domain.name == domain).values(password=hashed)
            )
            result = session.execute(stmt)
            if result.merge().rowcount != 1:
                raise ValueError(
                    f"Can't update password for non-existing domain {domain}"
                )
            session.commit()
        self.db_flag.touch()

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

        with Session(self.db) as session:
            stmt = sa.delete(Domain).where(Domain.name == domain)
            session.execute(stmt)
            session.commit()
        self.db_flag.touch()

    def set_last_query(self, data: dict[str, int]) -> int:
        rowsdata = [{"name": domain, "epoch": epoch} for domain, epoch in data.items()]
        with Session(self.db) as session:
            result = session.execute(sa.update(Domain), rowsdata)
        return len(result.fetchall())

    def iter(self, tld: str | None = None) -> Generator[Domain]:
        stmt = sa.select(Domain).order_by(Domain.name)
        if tld:
            stmt = stmt.where(Domain.name.like(f"%.{tld}"))
        with Session(self.db) as session:
            yield from session.execute(stmt).scalars()
