#!/usr/bin/env python3
from pathlib import Path

import yaml
from flask import Flask, jsonify, request
from flask.typing import ResponseReturnValue
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from .dynette import Dynette, ForbiddenError

CONFIG_FILE = Path.cwd() / "config.yml"


def trusted_ip() -> bool:
    # This is for example the CI, or developers testing new developments
    exempted_ips: list[str] = app.config.get("LIMIT_EXEMPTED_IPS", [])
    ips = (request.remote_addr, request.environ.get("HTTP_X_FORWARDED_HOST"))
    return any(ip in exempted_ips for ip in ips)


app = Flask(__name__)
app.config.from_file(str(CONFIG_FILE), load=yaml.safe_load)
# cf. https://flask-limiter.readthedocs.io/en/stable/recipes.html#deploying-an-application-behind-a-proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
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

DB_FOLDER = Path(app.config["DB_FOLDER"]).resolve()
assert DB_FOLDER.is_dir(), "You should create the DB folder declared in the config"

DYNETTE = Dynette(DB_FOLDER, app.config["DOMAINS"])

@app.route("/")
@limiter.exempt
def home() -> ResponseReturnValue:
    return "Wanna play the dynette?"


@app.route("/domains")
@limiter.exempt
def domains() -> ResponseReturnValue:
    return jsonify(app.config["DOMAINS"]), 200


@app.route("/test/<string:domain>")
@app.route("/domains/<string:domain>", methods=["GET"])
@limiter.limit("5 per hour", exempt_when=trusted_ip)
def availability(domain: str) -> ResponseReturnValue:
    try:
        DYNETTE.validate(domain)
    except (TypeError, ValueError) as err:
        return {"error": str(err)}, 400

    if not DYNETTE.available(domain):
        return {"error": f"Subdomain already taken: {domain}"}, 409

    return f'"Domain {domain} is available"', 200


@app.route("/domains/<string:subdomain>", methods=["POST"])
@limiter.limit("5 per hour", exempt_when=trusted_ip)
def register(subdomain: str) -> ResponseReturnValue:
    try:
        data = dict(request.form)
        recovery_password = request.form.get("recovery_password")
        key = request.form.get("key")
        assert isinstance(key, str)
        recovery_password = request.form.get("recovery_password")
    except (ValueError, AssertionError):
        return {"error": f"Invalid request: {data}"}, 400

    try:
        DYNETTE.validate(subdomain)
        if not DYNETTE.available(subdomain):
            return {"error": f"domain already taken: {subdomain}"}, 409
        DYNETTE.register(subdomain, key, recovery_password)

    except (TypeError, ValueError, AssertionError) as err:
        return {"error": str(err)}, 400
    except ForbiddenError:
        return '"Access Denied"', 403

    return '"OK"', 201


@app.route("/key/<string:key>", methods=["POST"])
@limiter.limit("5 per hour", exempt_when=trusted_ip)
def register_via_key(key: str) -> ResponseReturnValue:
    try:
        subdomain = request.form.get("subdomain")
        assert isinstance(subdomain, str)
    except (ValueError, AssertionError):
        return {"error": f"Invalid request: {request.form!r}"}, 400

    if (pwd := request.form.get("recovery_password")) is not None:
        request.form["recovery_password"] = pwd
    request.form["recovery_password"] = key

    return register(subdomain)


@app.route("/domains/<string:subdomain>", methods=["DELETE"])
@limiter.limit("5 per hour", exempt_when=trusted_ip)
def delete_using_recovery_password_or_key(subdomain: str) -> ResponseReturnValue:
    try:
        recovery_password = request.form.get("recovery_password")
        key = request.form.get("key")
        assert any(
            string and isinstance(string, str) for string in (key, recovery_password)
        )
    except (ValueError, AssertionError):
        return {"error": "Invalid request"}, 400

    try:
        DYNETTE.validate(subdomain)
        if DYNETTE.available(subdomain):
            return {"error": "Subdomain already deleted"}, 409
        DYNETTE.delete(subdomain, key, recovery_password)

    except (TypeError, ValueError, AssertionError) as err:
        return {"error": str(err)}, 400
    except ForbiddenError:
        return '"Access Denied"', 403

    return '"OK"', 200


@app.route("/domains/<string:subdomain>/recovery_password", methods=["PUT"])
@limiter.limit("5 per hour", exempt_when=trusted_ip)
def set_recovery_password_using_key(subdomain: str) -> ResponseReturnValue:
    try:
        recovery_password = request.form.get("recovery_password")
        key = request.form.get("key")
        assert recovery_password and isinstance(recovery_password, str)
        assert key and isinstance(key, str)
    except (ValueError, AssertionError):
        return {"error": "Invalid request"}, 400

    try:
        DYNETTE.validate(subdomain)
        if DYNETTE.available(subdomain):
            return {"error": "Subdomain not registered"}, 404
        DYNETTE.set_password(subdomain, key, recovery_password)

    except (TypeError, ValueError, AssertionError) as err:
        return {"error": str(err)}, 400
    except ForbiddenError:
        return '"Access Denied"', 403

    return '"OK"', 200
