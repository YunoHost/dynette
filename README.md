YunoHost DynDNS Server
======================


**Note: Tested on Debian wheezy and YunoHost 2.4 (should work on Ubuntu)**

Setup quickly
-------------------------------
You can use the dynette_ynh package for YunoHost
https://github.com/YunoHost-Apps/dynette_ynh


Manual setup
-------------------------------

```
git clone https://github.com/YunoHost/dynette
```


Web subscribe server deployment
-------------------------------

Install required stuff
```
$ apt-get install postgresql postgresql-server-dev-9.4 ruby thin libpq-dev bundler apache2 bind9 python
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


Apache configuration
--------------------

```
vim /etc/apache2/sites-available/dynette
```

Paste & change server name in below configuration:
```
<VirtualHost *:80>
  ServerName dyndns.yunohost.org

  RewriteEngine On

  <Proxy balancer://thinservers>
    BalancerMember http://127.0.0.1:5000
    BalancerMember http://127.0.0.1:5001
    BalancerMember http://127.0.0.1:5002
  </Proxy>

  # Redirect all non-static requests to thin
  RewriteCond %{DOCUMENT_ROOT}/%{REQUEST_FILENAME} !-f
  RewriteRule ^/(.*)$ balancer://thinservers%{REQUEST_URI} [P,QSA,L]

  ProxyPass / balancer://thinservers/
  ProxyPassReverse / balancer://thinservers/
  ProxyPreserveHost on

  <Proxy *>
    Order deny,allow
    Allow from all
  </Proxy>

  # Custom log file locations
  ErrorLog  /var/log/apache2/dynette-error.log
  CustomLog /var/log/apache2/dynette-access.log combined

</VirtualHost>
```

Enable apache2 sites & modules:
```
a2enmod proxy
a2enmod rewrite
a2ensite dynette
service apache2 restart
```

Alternative nginx configuration
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

Cron job configuration
----------------------

Edit dynette.cron.py and change settings:
```
# If you want to simply do test in local, use "http://127.0.0.1:5000/"
subs_urls = ['https://dyndns.yunohost.org']
ns0       = 'ns0.yunohost.org'
ns1       = 'ns1.yunohost.org'
```

Create and edit master.key file is Dynette directory
```
echo "MyMasterKey" > master.key
```

Create dynette log file
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

Adding a new subdomain
----------------------

- Add the domain in `DOMAINS` in dynette.rb
- Restart dynette (and/or thin ?)
- Check that https://dynette.tld/domains actually shows the new domain
- Test adding a new domain from YunoHost

Troobleshooting
---------------

If you run into troubles running the DNS server, try to check permissions on
`/var/lib/bind` and check if bind listens on 0.0.0.0 in
`/etc/bind/bind.conf.options`.
