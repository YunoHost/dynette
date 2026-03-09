#!/usr/bin/env python3

import argparse
import base64
import subprocess
from pathlib import Path

import jinja2
import yaml

from .dynette import Dynette


def encode_key(key: bytes) -> str:
    """
    Format the key as expected by Named:
    base64 but split as 56 chars, a space, the rest.
    """
    key64 = base64.b64encode(key).decode()
    return key64[:56] + " " + key64[56:]


def generate_named_conf(dynette: Dynette, file: Path) -> None:
    templates_dir = Path(__file__).resolve().parent / "templates"
    template_loader = jinja2.FileSystemLoader(searchpath=templates_dir)
    template_environ = jinja2.Environment(loader=template_loader)
    template = template_environ.get_template("named.conf.j2")

    domains = {domain: [] for domain in dynette.tlds}

    for domain, key, _ in dynette.iter():
        tld = next((tld for tld in dynette.tlds if domain.endswith(f".{tld}")), None)
        if tld is None:
            raise RuntimeError(f"Unknown domain {domain}, no tld matches!")
        domains[tld].append({"name": domain, "key": encode_key(key)})

    named_conf = template.render(domains=domains)
    file.write_text(named_conf)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=Path, default=Path("./config.yml"))
    parser.add_argument(
        "-o", "--output", type=Path, default=Path("/etc/bind/named.conf.local")
    )
    parser.add_argument(
        "-r", "--reload", action=argparse.BooleanOptionalAction, default=True
    )
    args = parser.parse_args()

    config = yaml.safe_load(args.config.open())
    db_path = Path(config["DB_PATH"])
    dynette = Dynette(db_path, config["DOMAINS"])

    generate_named_conf(dynette, args.output)

    if args.reload:
        subprocess.check_call(
            ["chown", "-R", "bind:bind", args.output, "/var/lib/bind/"]
        )
        subprocess.check_call(["rndc", "reload"])


if __name__ == "__main__":
    main()
