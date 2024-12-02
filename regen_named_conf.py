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
import yaml
import glob
import jinja2

config = yaml.safe_load(open("config.yml").read())

domains = [{"name": domain, "subdomains": []} for domain in config["DOMAINS"]]

for infos in domains:
    domain = infos["name"]
    for f in glob.glob(config["DB_FOLDER"] + f"*.{domain}.key"):
        key = open(f).read()
        subdomain = f.split("/")[-1].rsplit(".", 1)[0]
        infos["subdomains"].append({"name": subdomain, "key": key})

templateLoader = jinja2.FileSystemLoader(searchpath="./templates/")
templateEnv = jinja2.Environment(loader=templateLoader)
template = templateEnv.get_template("named.conf.j2")
named_conf = template.render(domains=domains)

open('/etc/bind/named.conf.local', 'w').write(named_conf)
os.system('chown -R bind:bind /etc/bind/named.conf.local /var/lib/bind/')
os.system('/usr/sbin/rndc reload')
