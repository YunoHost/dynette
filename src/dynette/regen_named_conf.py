#!/usr/bin/env python3

import subprocess
from pathlib import Path

import jinja2
import yaml

DYNETTE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = DYNETTE_DIR / "templates"

CONFIG_FILE = Path("./config.yml")


def main() -> None:
    config = yaml.safe_load(CONFIG_FILE.open())
    db_folder = Path(config["DB_FOLDER"])

    domains = [{"name": domain, "subdomains": []} for domain in config["DOMAINS"]]

    for infos in domains:
        domain = infos["name"]
        for file in db_folder.glob(f"*.{domain}.key"):
            subdomain = file.name.rsplit(".", 1)[0]
            key = file.read_text().strip()
            infos["subdomains"].append({"name": subdomain, "key": key})

    template_loader = jinja2.FileSystemLoader(searchpath=TEMPLATES_DIR)
    template_environ = jinja2.Environment(loader=template_loader)
    template = template_environ.get_template("named.conf.j2")

    named_conf = template.render(domains=domains)
    Path("/etc/bind/named.conf.local").write_text(named_conf)

    subprocess.check_call(
        ["chown", "-R", "bind:bind", "/etc/bind/named.conf.local", "/var/lib/bind/"]
    )
    subprocess.check_call(["/usr/sbin/rndc", "reload"])


if __name__ == "__main__":
    main()
