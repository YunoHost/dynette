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
