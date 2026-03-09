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
    dynette = Dynette(args.output, config["DOMAINS"])

    for item, keyfile in enumerate(db_folder.glob("*.key")):
        domain = keyfile.name.removesuffix(".key")
        print(f"{item}\t{domain}\r", end="")
        dynette.validate(domain)
        key = base64.b64decode(keyfile.read_text().replace(" ", ""))
        dynette.register(domain, key, None, commit=False)

        passwordfile = db_folder / f"{domain}.recovery_password"
        if passwordfile.exists():
            password = base64.b64decode(passwordfile.read_text()).decode()
            dynette.set_password(domain, b"", password, is_hashed=True, commit=False, check=False)

    dynette.db.commit()


if __name__ == "__main__":
    main()
