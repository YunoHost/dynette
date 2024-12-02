#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import base64
import hmac
import re
from pathlib import Path

import bcrypt
import yaml
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
import werkzeug.exceptions as httperr

SCRIPT_DIR = Path(__file__).resolve().parent

DOMAIN_REGEX = re.compile(
    r"^([a-z0-9]{1}([a-z0-9\-]*[a-z0-9])*)(\.[a-z0-9]{1}([a-z0-9\-]*[a-z0-9])*)*(\.[a-z]{1}([a-z0-9\-]*[a-z0-9])*)$"
)

app = Flask(__name__)
app.config.from_file(SCRIPT_DIR / "config.yml", load=yaml.safe_load)
# cf. https://flask-limiter.readthedocs.io/en/stable/recipes.html#deploying-an-application-behind-a-proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

DB_FOLDER = Path(app.config["DB_FOLDER"]).resolve()
assert DB_FOLDER.is_dir(), "You should create the DB folder declared in the config"


def trusted_ip() -> bool:
    # This is for example the CI, or developers testing new developments
    trusted_ips = app.config.get("LIMIT_EXEMPTED_IPS", [])
    return (
        request.remote_addr in trusted_ips
        or request.environ.get("HTTP_X_FORWARDED_HOST") in trusted_ips
    )


limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["50 per hour"],
    # storage_uri="memory://",   # <- For development
    storage_uri="redis://localhost:6379",
    storage_options={"socket_connect_timeout": 30},
    strategy="fixed-window",  # or "moving-window"
    application_limits_exempt_when=trusted_ip,
    default_limits_exempt_when=trusted_ip,
)


def _validate_subdomain(domain: str | None, should_be_taken: bool) -> None:
    if not isinstance(domain, str):
        raise httperr.BadRequest("subdomain was not sent properly")

    if not DOMAIN_REGEX.match(domain):
        raise httperr.BadRequest(f"This is not a valid domain: {domain}")

    if (
        len(domain.split(".")) != 3
        or domain.split(".", 1)[-1] not in app.config["DOMAINS"]
    ):
        raise httperr.BadRequest("This domain is not handled by this dynette server.")

    taken = _is_available(domain)
    if taken and not should_be_taken:
        raise httperr.Conflict(f"Subdomain already registered: {domain}")
    if not taken and should_be_taken:
        raise httperr.Conflict(f"Subdomain not registered: {domain}")


def _is_available(domain) -> bool:
    key_file = DB_FOLDER / f"{domain}.key"
    return not key_file.exists()


def _decode_key_b64(key_b64: str) -> str:
    try:
        key = base64.b64decode(key_b64).decode()
        if len(key) != 89:
            raise httperr.BadRequest("Key format is invalid")
        return key
    except Exception:
        raise httperr.BadRequest("Key format is invalid")


def _validate_recovery_password(password: str | None) -> None:
    if not isinstance(password, str):
        raise httperr.BadRequest("Recovery password was not sent properly")
    if len(password) < 8:
        raise httperr.Conflict("Recovery password too short")
    if len(password) > 1024:
        raise httperr.Conflict("Recovery password too long")


@app.route("/")
@limiter.exempt
def home():
    return "Wanna play the dynette?"


@app.route("/domains")
@limiter.exempt
def domains():
    return jsonify(app.config["DOMAINS"]), 200


@app.route("/test/<string:domain>")
@limiter.limit("50 per hour", exempt_when=trusted_ip)
def availability(domain: str):
    _validate_subdomain(domain, False)
    return f'"Domain {domain} is available"', 200


@app.route("/key/<string:key>", methods=["POST"])
@limiter.limit("5 per hour", exempt_when=trusted_ip)
def register(key: str):
    key = _decode_key_b64(key)
    subdomain = request.form.get("subdomain")
    password = request.form.get("recovery_password")
    _validate_subdomain(subdomain, False)

    key_file = DB_FOLDER / f"{subdomain}.key"
    recovery_file = DB_FOLDER / f"{subdomain}.recovery_password"

    key_file.write_text(key)

    if password:
        _validate_recovery_password(password)
        pw_hashed = bcrypt.hashpw(password=password.encode(), salt=bcrypt.gensalt(14))
        pw_hashed_b64 = base64.b64encode(pw_hashed).decode()
        recovery_file.write_text(pw_hashed_b64)

    return '"OK"', 201


@app.route("/domains/<string:subdomain>", methods=["DELETE"])
@limiter.limit("5 per hour", exempt_when=trusted_ip)
def delete_using_recovery_password_or_key(subdomain: str):
    _validate_subdomain(subdomain, True)
    key_b64 = request.form.get("key")
    recovery_password = request.form.get("recovery_password")

    key_file = DB_FOLDER / f"{subdomain}.key"
    recovery_file = DB_FOLDER / f"{subdomain}.recovery_password"

    if key_b64:
        if not hmac.compare_digest(_decode_key_b64(key_b64), key_file.read_text()):
            raise httperr.Forbidden("Access denied")

    elif recovery_password:
        if not recovery_file.exists():
            raise httperr.Forbidden("Access denied")
        hashed = base64.b64decode(recovery_file.read_text())
        if not bcrypt.checkpw(recovery_password.encode(), hashed):
            raise httperr.Forbidden("Access denied")

    else:
        raise httperr.Forbidden("key or recovery_password needed")

    if key_file.exists():
        key_file.unlink()
    if recovery_file.exists():
        recovery_file.unlink()

    return '"OK"', 200


@app.route("/domains/<string:subdomain>/recovery_password", methods=["PUT"])
@limiter.limit("5 per hour", exempt_when=trusted_ip)
def set_recovery_password_using_key(subdomain: str):
    _validate_subdomain(subdomain, True)
    key_b64 = request.form.get("key")
    recovery_password = request.form.get("recovery_password")

    if not key_b64:
        raise httperr.BadRequest("key is required.")
    _validate_recovery_password(recovery_password)

    key_file = DB_FOLDER / f"{subdomain}.key"
    recovery_file = DB_FOLDER / f"{subdomain}.recovery_password"

    if not hmac.compare_digest(_decode_key_b64(key_b64), key_file.read_text()):
        raise httperr.Forbidden("Access denied")

    hashed = bcrypt.hashpw(password=recovery_password.encode(), salt=bcrypt.gensalt(14))
    hashed_b64 = base64.b64encode(hashed).decode()
    recovery_file.write_text(hashed_b64)

    return '"OK"', 200
