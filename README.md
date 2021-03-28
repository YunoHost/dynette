YunoHost DynDNS Server
======================

Setup quickly
-------------------------------

You can use the dynette_ynh package for YunoHost
https://github.com/YunoHost-Apps/dynette_ynh

Web subscribe server deployment
-------------------------------

Install required stuff
```
$ apt install postgresql postgresql-server-dev-all ruby thin libpq-dev bundler nginx bind9 python3
```

Prepare user dynette
```
$ useradd dynette
$ passwd dynette
$ mkdir /home/dynette
$ chown -R dynette:dynette /home/dynette
```

Prepare PostgreSQL database
```
$ su - postgres
$ psql template1
template1=# CREATE USER dynette WITH PASSWORD 'verySecurePassword';
template1=# CREATE DATABASE dynette;
template1=# GRANT ALL PRIVILEGES ON DATABASE dynette to dynette;
template1=# \q
```

Install dynette
```
$ cd /home/dynette
$ git clone https://github.com/YunoHost/dynette
$ cd dynette
$ bundle install
```

Edit dynette.rb, change PostgreSQL password and domains handled, line 11-12:
```
DataMapper.setup(:default, ENV['DATABASE_URL'] || "postgres://dynette:myPassword@localhost/dynette")
DOMAINS = ["nohost.me", "noho.st"]
```

Configure and launch thin
```
thin config -C /etc/thin2.1/dynette.yml -c /home/dynette/dynette/ --servers 3 -p 5000 -e production
service thin restart
```

nginx configuration
--------------------
Alternatively you can use nginx

```
upstream dynette {
	  server 127.0.0.1:5000;
	  server 127.0.0.1:5001;
	  server 127.0.0.1:5002;
}

server {
	  listen   80;
	  server_name dyndns.yunohost.org;

	  access_log /var/www/dyndns.yunohost.org/log/access.log;
	  error_log  /var/www/dyndns.yunohost.org/log/error.log;
	  root     /var/www/dyndns.yunohost.org;
	  index    index.html;

	  location / {
        try_files $uri dynette-ruby;
    }

    location @dynette-ruby {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect  off;
        proxy_pass http://dynette;
    }
}
```

Configure
---------

`cp config.file.j2 config.file` and fill all the info

```
touch /var/log/dynette.log
```

Enable cronjob for dynette (crontab -e)
```
* * * * * /path/to/dynette/dynette.cron.py >> /var/log/dynette.log 2>&1
```

Test it's working
-----------------

`wget -q -O - http://127.0.0.1:5000/test/someDomain.nohost.me`

Troobleshooting
---------------

If you run into troubles running the DNS server, try to check permissions on
`/var/lib/bind` and check if bind listens on 0.0.0.0 in
`/etc/bind/bind.conf.options`.
