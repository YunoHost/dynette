#!/usr/bin/env python3

import base64
import contextlib
import json
import os
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient, FlaskCliRunner

from dynette.app import create_app


@contextlib.contextmanager
def working_directory(path: Path) -> Generator:
    """Changes working directory and returns to previous on exit."""
    prev_cwd = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(prev_cwd)


@pytest.fixture()
def app() -> Generator[Flask, None, None]:
    with (
        tempfile.TemporaryDirectory() as tempdir_str,
        working_directory(tempdir := Path(tempdir_str)),
    ):
        (tempdir / "config.yml").touch()
        app = create_app(
            {
                "DOMAINS": ["test.tld"],
                "LIMIT_EXEMPTED_IPS": [],
                "TESTING": True,
                "DB_FOLDER": tempdir,
            }
        )

        # other setup can go here

        yield app

        # clean up / reset resources here


@pytest.fixture()
def client(app: Flask) -> FlaskClient:
    return app.test_client()


@pytest.fixture()
def runner(app: Flask) -> FlaskCliRunner:
    return app.test_cli_runner()


@pytest.fixture()
def valid_key() -> str:
    return base64.b64encode(("a" * 64).encode()).decode()


@pytest.fixture()
def valid_key_2() -> str:
    return base64.b64encode(("b" * 64).encode()).decode()


def format_key(key64: str) -> str:
    # Mimic what's done in yunohost
    secret = f"{key64[:56]} {key64[56:]}"
    return base64.b64encode(secret.encode()).decode()


def test_home(client: FlaskClient) -> None:
    response = client.get("/")
    assert response.data.decode() == "Wanna play the dynette?"


def test_list(client: FlaskClient) -> None:
    response = client.get("/domains")
    data = response.json
    assert isinstance(data, list) and (isinstance(elt, str) for elt in data)


def test_available(client: FlaskClient) -> None:
    domain = "anydomain.test.tld"
    response = client.get(f"/test/{domain}")
    responseother = client.get(f"/domains/{domain}")
    assert response.data == responseother.data

    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, str)
    assert data.endswith("is available")


INVALID_KEYS: list[str] = [
    "a" * 64,
    base64.b64encode(("a" * 63).encode()).decode(),
    base64.b64encode(("a" * 65).encode()).decode(),
]


@pytest.mark.parametrize("key", INVALID_KEYS)
def test_invalid_key(client: FlaskClient, key: str) -> None:
    domain = "anydomain.test.tld"
    response = client.post(f"/domains/{domain}", data={"key": key})
    assert response.status_code == 400, response.json
    data = response.json
    assert isinstance(data, dict)
    assert isinstance(data["error"], str)


def test_register1(client: FlaskClient, valid_key: str) -> None:
    domain = "anydomain.test.tld"
    response = client.post(f"/domains/{domain}", data={"key": format_key(valid_key)})
    assert response.status_code == 201, response.json


def test_register2(client: FlaskClient, valid_key: str) -> None:
    domain = "anydomain.test.tld"
    response = client.post(f"/key/{format_key(valid_key)}", data={"subdomain": domain})
    assert response.status_code == 201, response.json


def test_register_makes_unavailable(client: FlaskClient, valid_key: str) -> None:
    domain = "anydomain.test.tld"
    assert client.get(f"/domains/{domain}").status_code == 200

    response = client.post(f"/key/{format_key(valid_key)}", data={"subdomain": domain})
    assert response.status_code == 201, response.json

    assert client.get(f"/domains/{domain}").status_code == 409

    response = client.delete(f"/domains/{domain}", data={"key": format_key(valid_key)})
    assert response.status_code == 200, response.json

    assert client.get(f"/domains/{domain}").status_code == 200


def test_wrong_key(client: FlaskClient, valid_key: str, valid_key_2: str) -> None:
    domain = "anydomain.test.tld"
    response = client.post(f"/key/{format_key(valid_key)}", data={"subdomain": domain})
    assert response.status_code == 201, response.json

    data = {"key": format_key(valid_key_2), "recovery_password": "a"}
    response = client.put(f"/domains/{domain}/recovery_password", data=data)
    assert response.status_code == 403, response.json

    response = client.delete(
        f"/domains/{domain}", data={"key": format_key(valid_key_2)}
    )
    assert response.status_code == 403, response.json

    response = client.delete(f"/domains/{domain}", data={"key": format_key(valid_key)})
    assert response.status_code == 200, response.json


def test_password(client: FlaskClient, valid_key: str) -> None:
    domain = "anydomain.test.tld"
    password = "some password with 'special & chars'"
    response = client.post(
        f"/key/{format_key(valid_key)}",
        data={"subdomain": domain, "recovery_password": password},
    )
    assert response.status_code == 201, response.json

    response = client.delete(f"/domains/{domain}", data={"recovery_password": password})
    assert response.status_code == 200, response.json

    assert client.get(f"/domains/{domain}").status_code == 200
    data = {"key": format_key(valid_key), "recovery_password": password}
    response = client.put(f"/domains/{domain}/recovery_password", data=data)
    assert response.status_code == 404, response.json

    response = client.post(f"/key/{format_key(valid_key)}", data={"subdomain": domain})
    assert response.status_code == 201, response.json

    data = {"key": format_key(valid_key), "recovery_password": password}
    response = client.put(f"/domains/{domain}/recovery_password", data=data)
    assert response.status_code == 200, response.json

    response = client.delete(f"/domains/{domain}", data={"recovery_password": password})
    assert response.status_code == 200, response.json

    assert client.get(f"/domains/{domain}").status_code == 200
