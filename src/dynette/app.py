#!/usr/bin/env python3

from pathlib import Path
from typing import Any

import yaml
from flask import Flask, jsonify, request
from flask.typing import ResponseReturnValue
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from .dynette import Dynette, ForbiddenError

CONFIG_FILE = Path.cwd() / "config.yml"


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    if test_config is None:
        app.config.from_file(str(CONFIG_FILE), load=yaml.safe_load)
    else:
        app.config.from_mapping(test_config)

    # cf. https://flask-limiter.readthedocs.io/en/stable/recipes.html#deploying-an-application-behind-a-proxy
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)  # type: ignore

    def trusted_ip() -> bool:
        # This is for example the CI, or developers testing new developments
        exempted_ips: list[str] = app.config.get("LIMIT_EXEMPTED_IPS", [])
        ips = (request.remote_addr, request.environ.get("HTTP_X_FORWARDED_HOST"))
        return any(ip in exempted_ips for ip in ips)

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

    db_folder = Path(app.config["DB_FOLDER"]).resolve()
    assert db_folder.is_dir(), "You should create the DB folder declared in the config"

    dynette = Dynette(db_folder, app.config["DOMAINS"])

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
            dynette.validate(domain)
        except (TypeError, ValueError) as err:
            return {"error": str(err)}, 400

        if not dynette.available(domain):
            return {"error": f"Subdomain already taken: {domain}"}, 409

        return f'"Domain {domain} is available"', 200

    def _register(
        subdomain: str | None, key: str | None, pwd: str | None
    ) -> ResponseReturnValue:
        if not (
            isinstance(subdomain, str)
            and isinstance(key, str)
            and isinstance(pwd, str | None)
        ):
            return {"error": f"Invalid request: {dict(request.form)}"}, 400

        try:
            dynette.validate(subdomain)
            if not dynette.available(subdomain):
                return {"error": f"domain already taken: {subdomain}"}, 409
            dynette.register(subdomain, key, pwd)
        except (TypeError, ValueError) as err:
            return {"error": str(err)}, 400
        except ForbiddenError:
            return '"Access Denied"', 403
        return '"OK"', 201

    @app.route("/domains/<string:subdomain>", methods=["POST"])
    @limiter.limit("5 per hour", exempt_when=trusted_ip)
    def register(subdomain: str) -> ResponseReturnValue:
        key = request.form.get("key")
        recovery_password = request.form.get("recovery_password")
        return _register(subdomain, key, recovery_password)

    @app.route("/key/<string:key>", methods=["POST"])
    @limiter.limit("5 per hour", exempt_when=trusted_ip)
    def register_via_key(key: str) -> ResponseReturnValue:
        subdomain = request.form.get("subdomain")
        recovery_password = request.form.get("recovery_password")
        return _register(subdomain, key, recovery_password)

    @app.route("/domains/<string:subdomain>", methods=["DELETE"])
    @limiter.limit("5 per hour", exempt_when=trusted_ip)
    def delete_using_recovery_password_or_key(subdomain: str) -> ResponseReturnValue:
        key = request.form.get("key")
        recovery_password = request.form.get("recovery_password")
        if not (isinstance(key, str) or isinstance(recovery_password, str)):
            return {"error": f"Invalid request: {dict(request.form)}"}, 400

        try:
            dynette.validate(subdomain)
            if dynette.available(subdomain):
                return {"error": "Subdomain already deleted"}, 409
            dynette.delete(subdomain, key, recovery_password)

        except (TypeError, ValueError) as err:
            return {"error": str(err)}, 400
        except ForbiddenError:
            return '"Access Denied"', 403

        return '"OK"', 200

    @app.route("/domains/<string:subdomain>/recovery_password", methods=["PUT"])
    @limiter.limit("5 per hour", exempt_when=trusted_ip)
    def set_recovery_password_using_key(subdomain: str) -> ResponseReturnValue:
        key = request.form.get("key")
        recovery_password = request.form.get("recovery_password")
        if not (isinstance(key, str) and isinstance(recovery_password, str)):
            return {"error": f"Invalid request: {dict(request.form)}"}, 400

        try:
            dynette.validate(subdomain)
            if dynette.available(subdomain):
                return {"error": "Subdomain not registered"}, 404
            dynette.set_password(subdomain, key, recovery_password)

        except (TypeError, ValueError) as err:
            return {"error": str(err)}, 400
        except ForbiddenError:
            return '"Access Denied"', 403

        return '"OK"', 200

    return app
