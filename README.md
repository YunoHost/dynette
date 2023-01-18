


### Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

### Dev


```bash
FLASK_APP=app.py flask run
```


### Production

- You should also install bind9
- Include `/etc/bind/named.conf.local` in `/etc/bind/named.conf`
- Install the following services

##### `dynette.service`

```
# Systemd config
[Unit]
Description=Dynette gunicorn daemon
After=network.target

[Service]
PIDFile=/run/gunicorn/dynette-pid
User=dynette
Group=dynette
WorkingDirectory=/var/www/dynette
ExecStart=/var/www/dynette/venv/bin/gunicorn -c /var/www/dynette/gunicorn.py wsgi:app
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

##### `dynette-regen-named-conf.service`

```
[Unit]
Description=Dynette named.conf regen
After=network.target
StartLimitIntervalSec=10
StartLimitBurst=5

[Service]
Type=oneshot
WorkingDirectory=/var/www/dynette
ExecStart=/var/www/dynette/venv/bin/python3 /var/www/dynette/regen_named_conf.py
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

##### `dynette-regen-named-conf.path`

```
[Path]
Unit=dynette-regen-named-conf.service
PathChanged=/var/dynette/db/ 

[Install]
WantedBy=multi-user.target
```

##### NGINX conf snippet

```
location / {
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_redirect  off;
    proxy_pass http://unix:/var/www/dynette/sock;
    proxy_read_timeout 210s;
}
```

### If we ever decide to add another base domain

We should initialize `/var/lib/bind/BASE_DOMAIN.db` (replace `BASE_DOMAIN` with e.g. nohost.me) with:

```text
$ORIGIN .
$TTL 10	; 10 seconds
BASE_DOMAIN		IN SOA	ns0.yunohost.org. hostmaster.yunohost.org. (
				1006380    ; serial
				10800      ; refresh (3 hours)
				3600       ; retry (1 hour)
				604800     ; expire (1 week)
				10         ; minimum (10 seconds)
				)
$TTL 3600	; 1 hour
			NS	ns0.yunohost.org.
			NS	ns1.yunohost.org.
$ORIGIN BASE_DOMAIN.
```
