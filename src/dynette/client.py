#!/usr/bin/env python3

import argparse
import base64
import hashlib

import requests


class DynetteClient:
    def __init__(self, server: str) -> None:
        if "://" not in server:
            server = f"https://{server}"
        self.server = server

    def _raise_err(self, response: requests.Response) -> None:
        if response.status_code is None or response.status_code >= 400:
            msg: str | dict[str, str] = response.json()
            if isinstance(msg, dict):
                msg = msg["error"]
            raise RuntimeError(msg)

    def _data(
        self, domain: str, key: str | None, password: str | None
    ) -> dict[str, str]:
        data = {}
        if key:
            data["key"] = base64.b64encode(key.encode()).decode()
        if password:
            hashpwd = hashlib.sha256(f"{domain}:{password}".encode())
            data["recovery_password"] = hashpwd.hexdigest()
        return data

    def tlds(self) -> list[str]:
        response = requests.get(f"{self.server}/domains", verify=False)
        response.raise_for_status()
        return response.json()

    def available(self, domain: str) -> bool:
        response = requests.get(f"{self.server}/domains/{domain}", verify=False)
        return response.status_code == 200

    def register(self, domain: str, key: str | None, password: str | None) -> None:
        assert key is not None
        assert len(key) == 64
        data = self._data(domain, key, password)
        response = requests.post(
            f"{self.server}/domains/{domain}?", data=data, verify=False
        )
        self._raise_err(response)

    def unregister(self, domain: str, key: str | None, password: str | None) -> None:
        data = self._data(domain, key, password)
        response = requests.delete(
            f"{self.server}/domains/{domain}", data=data, verify=False
        )
        self._raise_err(response)

    def chpwd(self, domain: str, key: str | None, password: str | None) -> None:
        response = requests.put(
            f"{self.server}/domains/{domain}/recovery_password",
            data=self._data(domain, key, password),
            verify=False,
        )
        self._raise_err(response)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dynette", type=str, help="Dynette server")
    parser.add_argument(
        "action",
        type=str,
        choices=["tlds", "available", "register", "unregister", "password"],
    )
    parser.add_argument("-d", "--domain", type=str)
    parser.add_argument("-k", "--key", type=str)
    parser.add_argument("-p", "--password", type=str)

    args = parser.parse_args()

    client = DynetteClient(args.dynette)

    match args.action:
        case "tlds":
            print(client.tlds())
        case "available":
            print(client.available(args.domain))
        case "register":
            if client.register(args.domain, args.key, args.password):
                print("OK")
        case "unregister":
            if client.unregister(args.domain, args.key, args.password):
                print("OK")
        case "password":
            if client.chpwd(args.domain, args.key, args.password):
                print("OK")


if __name__ == "__main__":
    main()
