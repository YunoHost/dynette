import hmac
import base64
import os
import re
import yaml
import bcrypt

from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix


DOMAIN_REGEX = re.compile(
    r"^([a-z0-9]{1}([a-z0-9\-]*[a-z0-9])*)(\.[a-z0-9]{1}([a-z0-9\-]*[a-z0-9])*)*(\.[a-z]{1}([a-z0-9\-]*[a-z0-9])*)$"
)

app = Flask(__name__)
app.config.from_file("config.yml", load=yaml.safe_load)
# cf. https://flask-limiter.readthedocs.io/en/stable/recipes.html#deploying-an-application-behind-a-proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["50 per hour"],
    storage_uri="memory://",
)

assert os.path.isdir(
    app.config["DB_FOLDER"]
), "You should create the DB folder declared in the config"


def _validate_domain(domain):

    if not DOMAIN_REGEX.match(domain):
        return {"error": f"This is not a valid domain: {domain}"}, 400

    if (
        len(domain.split(".")) != 3
        or domain.split(".", 1)[-1] not in app.config["DOMAINS"]
    ):
        return {"error": "This subdomain is not handled by this dynette server."}, 400


def _is_available(domain):

    return not os.path.exists(f"{app.config['DB_FOLDER']}/{domain}.key")


@app.route("/")
@limiter.exempt
def home():
    return "Wanna play the dynette?"


@app.route("/domains")
@limiter.exempt
def domains():
    return jsonify(app.config["DOMAINS"]), 200


@app.route("/test/<domain>")
@limiter.limit("3 per minute")
def availability(domain):

    error = _validate_domain(domain)
    if error:
        return error

    if _is_available(domain):
        return f'"Domain {domain} is available"', 200
    else:
        return {"error": f"Subdomain already taken: {domain}"}, 409


@app.route("/key/<key>", methods=["POST"])
@limiter.limit("5 per hour")
def register(key):

    try:
        key = base64.b64decode(key).decode()
    except Exception as e:
        return {"error": "Key format is invalid"}, 400
    else:
        if len(key) != 89:
            return {"error": "Key format is invalid"}, 400

    try:
        data = dict(request.form)  # get_json(force=True)
        subdomain = data.get("subdomain")
        assert isinstance(subdomain, str)
    except Exception as e:
        return {"error": f"Invalid request: {str(request.form)}"}, 400

    error = _validate_domain(subdomain)
    if error:
        return error

    if not _is_available(subdomain):
        return {"error": f"Subdomain already taken: {subdomain}"}, 409

    recovery_password = data.get("recovery_password")
    if recovery_password and isinstance(recovery_password, str):
        if len(recovery_password) < 8:
            return {"error": "Recovery password too short"}, 409
        if len(recovery_password) > 1024:
            return {"error": "Recovery password too long"}, 409

        recovery_password = bcrypt.hashpw(
            password=recovery_password.encode(), salt=bcrypt.gensalt(14)
        )
        recovery_password = base64.b64encode(recovery_password).decode()

    with open(f"{app.config['DB_FOLDER']}/{subdomain}.key", "w") as f:
        f.write(key)

    if recovery_password:
        with open(f"{app.config['DB_FOLDER']}/{subdomain}.recovery_password", "w") as f:
            f.write(recovery_password)

    return '"OK"', 201


@app.route("/domains/<subdomain>", methods=["DELETE"])
@limiter.limit("5 per hour")
def delete_using_recovery_password_or_key(subdomain):

    try:
        assert isinstance(subdomain, str)
        data = dict(request.form)  # get_json(force=True)
        recovery_password = data.get("recovery_password")
        key = data.get("key")
        assert (recovery_password and isinstance(recovery_password, str)) or (
            key and isinstance(key, str)
        )
        if key:
            key = base64.b64decode(key).decode()
    except Exception:
        return {"error": "Invalid request"}, 400

    error = _validate_domain(subdomain)
    if error:
        return error

    if _is_available(subdomain):
        return {"error": "Subdomain already deleted"}, 409

    if key:
        with open(f"{app.config['DB_FOLDER']}/{subdomain}.key") as f:
            if not hmac.compare_digest(key, f.read()):
                return '"Access denied"', 403
    elif recovery_password:
        if not os.path.exists(
            f"{app.config['DB_FOLDER']}/{subdomain}.recovery_password"
        ):
            return '"Access denied"', 403
        with open(f"{app.config['DB_FOLDER']}/{subdomain}.recovery_password") as f:
            hashed = base64.b64decode(f.read())

        if not bcrypt.checkpw(recovery_password.encode(), hashed):
            return '"Access denied"', 403
    # Shouldnt happen, this is checked before
    else:
        return '"Access denied"', 403

    if os.path.exists(f"{app.config['DB_FOLDER']}/{subdomain}.key"):
        os.remove(f"{app.config['DB_FOLDER']}/{subdomain}.key")
    if os.path.exists(f"{app.config['DB_FOLDER']}/{subdomain}.recovery_password"):
        os.remove(f"{app.config['DB_FOLDER']}/{subdomain}.recovery_password")

    return '"OK"', 200


@app.route("/domains/<subdomain>/recovery_password", methods=["PUT"])
@limiter.limit("5 per hour")
def set_recovery_password_using_key(subdomain):

    try:
        assert isinstance(subdomain, str)
        data = dict(request.form)  # get_json(force=True)
        recovery_password = data.get("recovery_password")
        key = data.get("key")
        assert (recovery_password and isinstance(recovery_password, str)) and (
            key and isinstance(key, str)
        )
        if key:
            key = base64.b64decode(key).decode()
    except Exception:
        return {"error": "Invalid request"}, 400

    error = _validate_domain(subdomain)
    if error:
        return error

    if _is_available(subdomain):
        return {"error": "Subdomain not registered"}, 404

    with open(f"{app.config['DB_FOLDER']}/{subdomain}.key") as f:
        if not hmac.compare_digest(key, f.read()):
            return '"Access denied"', 403

    if len(recovery_password) < 8:
        return {"error": "Recovery password too short"}, 409
    if len(recovery_password) > 1024:
        return {"error": "Recovery password too long"}, 409

    recovery_password = bcrypt.hashpw(
        password=recovery_password.encode(), salt=bcrypt.gensalt(14)
    )
    recovery_password = base64.b64encode(recovery_password).decode()

    with open(f"{app.config['DB_FOLDER']}/{subdomain}.recovery_password", "w") as f:
        f.write(recovery_password)

    return '"OK"', 200
