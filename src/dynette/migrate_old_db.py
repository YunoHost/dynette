#!/usr/bin/env python3

import argparse
import base64
from pathlib import Path

import yaml

from .dynette import Dynette


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=Path, default=Path("config.yml"))
    parser.add_argument("-o", "--output", type=Path, default=Path("domains.sql"))
    args = parser.parse_args()

    config = yaml.safe_load(args.config.open())
    db_folder = Path(config["DB_FOLDER"])
    dynette = Dynette(db_folder, config["DOMAINS"])

    for keyfile in db_folder.glob("*.key"):
        domain = keyfile.name.removeprefix(".key")
        passwordfile = db_folder / f"{domain}.recovery_password"
        key = base64.b64decode(keyfile.read_text().replace(" ", ""))
        if passwordfile.exists():
            password = base64.b64decode(passwordfile.read_text()).decode()
        else:
            password = None

        dynette.register(domain, key, password, commit=False)
    dynette.db.commit()


if __name__ == "__main__":
    main()
