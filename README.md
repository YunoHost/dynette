YunoHost DynDNS Server
======================


**Note: Tested on Debian wheezy (should work on Ubuntu)**

```
git clone https://github.com/YunoHost/dynette
```


Web subscribe server deployment
-------------------------------
```
apt-get install postgresql ruby thin libpq-dev bundler apache2
```

In dynette repository:
```
bundle install
```

Thin configuration:
```
thin config -C /etc/thin1.9.1/dynette.yml -c /path/to/dynette/ --servers 3 -p 5000 -e production
```

Apache configuration:
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

PostgreSQL configuration:
```
# adduser dynette
# passwd dynette
# su - postgres
$ psql template1
template1=# CREATE USER dynette WITH PASSWORD 'myPassword';
template1=# CREATE DATABASE dynette;
template1=# GRANT ALL PRIVILEGES ON DATABASE dynette to dynette;
template1=# \q
```

Edit dynette.rb, change PostgreSQL password and domains handled, line 11-12:
```
DataMapper.setup(:default, ENV['DATABASE_URL'] || "postgres://dynette:myPassword@localhost/dynette")
DOMAINS = ["nohost.me", "noho.st"]
```

Enable apache2 sites & modules:
```
a2enmod proxy
a2enmod rewrite
a2ensite dynette
service thin start
service apache2 restart
```


DNS configuration
-----------------

```
apt-get install bind9 python
```

Edit dynette.cron.py and change settings:
```
subs_urls = ['http://dyndns.yunohost.org']  
ns1       = 'dynhost.yunohost.org'          
ns2       = 'hostmaster.yunohost.org'
```

Create dynette log file
```
touch /var/log/dynette.log
```

Enable cronjob for dynette (crontab -e)
```
* * * * * /path/to/dynette/dynette.cron.py >> /var/log/dynette.log 2>&1
```


Troobleshooting
---------------

If you run into troubles running the DNS server, try to check permissions on /var/lib/bind and check if bind listens on 0.0.0.0 (in /etc/bind/bind.conf.options)
