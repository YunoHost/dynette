#!/usr/bin/env python3

import argparse
import base64
import subprocess
from pathlib import Path

import jinja2

from .config import Config
from .dynette import Dynette


class Bind9Config:
    def __init__(self, named_conf_dir: Path, named_data_dir: Path) -> None:
        self.named_conf_dir = named_conf_dir.resolve()
        self.named_data_dir = named_data_dir.resolve()
        templates_dir = Path(__file__).resolve().parent / "templates"
        template_loader = jinja2.FileSystemLoader(searchpath=templates_dir)
        self.template_environ = jinja2.Environment(
            loader=template_loader, keep_trailing_newline=True
        )

    def gen_named_conf(self) -> None:
        output = self.named_conf_dir / "named.conf.local"
        template = self.template_environ.get_template("named.conf.local.j2")
        output.write_text(template.render(named_conf_dir=self.named_conf_dir))

    def gen_tld_conf(self, tld: str, domains: list[tuple[str, str]]) -> None:
        output = self.named_conf_dir / "domains" / f"{tld}.conf"
        output.parent.mkdir(exist_ok=True)
        template = self.template_environ.get_template("tld.conf.j2")
        output.write_text(
            template.render(
                tld=tld,
                domains=domains,
                # key=self.encode_key(key),
                named_data_dir=self.named_data_dir,
            )
        )

    def gen_zone_db(self, tld: str, domain: str) -> None:
        output = self.named_data_dir / tld / f"{domain}.db"
        if output.exists():
            return
        output.parent.mkdir(exist_ok=True)
        template = self.template_environ.get_template("zone.db.j2")
        output.write_text(template.render(domain=domain))

    @staticmethod
    def encode_key(key: bytes) -> str:
        """
        Format the key as expected by Named:
        base64 but split as 56 chars, a space, the rest.
        """
        key64 = base64.b64encode(key).decode()
        return key64[:56] + " " + key64[56:]


# def generate_named_conf(dynette: Dynette, file: Path) -> None:
#     domains = {domain: [] for domain in dynette.tlds}

#     generator = Bind9Config()

#     for domain, key, _ in dynette.iter():
#         tld = next((tld for tld in dynette.tlds if domain.endswith(f".{tld}")), None)
#         if tld is None:
#             raise RuntimeError(f"Unknown domain {domain}, no tld matches!")
#         domains[tld].append({"name": domain, "key": encode_key(key)})

#     named_conf = template.render(domains=domains)
#     file.write_text(named_conf)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=Path, default=Path("config.yml"))
    parser.add_argument("-b", "--bind-conf-dir", type=Path)
    parser.add_argument("-d", "--bind-data-dir", type=Path)
    parser.add_argument(
        "-r", "--reload", action=argparse.BooleanOptionalAction, default=True
    )
    args = parser.parse_args()
    config = Config(args.config)

    dynette = Dynette(config.database, config.tlds)
    dynette.init()
    dynette.db_flag.unlink(missing_ok=True)

    conf_dir: Path = args.bind_conf_dir or config.bind.config_dir
    data_dir: Path = args.bind_data_dir or config.bind.database_dir
    generator = Bind9Config(conf_dir, data_dir)
    generator.gen_named_conf()

    for tld in config.tlds:
        domains = [
            (domain.name, generator.encode_key(domain.key))
            for domain in dynette.iter(tld)
        ]
        generator.gen_tld_conf(tld, domains)
        for domain, _ in domains:
            generator.gen_zone_db(tld, domain)

    if args.reload:
        subprocess.check_call(["chown", "-R", "bind:bind", conf_dir, data_dir])
        subprocess.check_call(["rndc", "reload"])


if __name__ == "__main__":
    main()
