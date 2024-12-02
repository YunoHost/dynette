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

import os
from pathlib import Path

import jinja2
import yaml

SCRIPT_DIR = Path(__file__).resolve().parent

CONFIG = yaml.safe_load((SCRIPT_DIR / "config.yml").read_text())


def subdomains_of(domain: str) -> list[dict[str, str]]:
    db_folder = Path(CONFIG["DB_FOLDER"]).resolve()

    return [
        {"name": keyfile.stem, "key": keyfile.read_text()}
        for keyfile in db_folder.glob(f"*.{domain}.key")
    ]


def main() -> None:
    domains = [
        {"name": domain, "subdomains": [subdomains_of(domain)]}
        for domain in CONFIG["DOMAINS"]
    ]

    templateLoader = jinja2.FileSystemLoader(searchpath=SCRIPT_DIR / "templates")
    templateEnv = jinja2.Environment(loader=templateLoader)
    template = templateEnv.get_template("named.conf.j2")
    named_conf = template.render(domains=domains)

    Path("/etc/bind/named.conf.local").write_text(named_conf)
    os.system("chown -R bind:bind /etc/bind/named.conf.local /var/lib/bind/")
    os.system("/usr/sbin/rndc reload")


if __name__ == "__main__":
    main()
