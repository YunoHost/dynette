command = "/var/www/dynette/venv/bin/gunicorn"
pythonpath = "/var/www/dynette"
workers = 4
user = "dynette"
bind = "unix:/var/www/dynette/sock"
pid = "/run/gunicorn/dynette-pid"
errorlog = "/var/log/dynette/error.log"
accesslog = "/var/log/dynette/access.log"
access_log_format = '%({X-Real-IP}i)s %({X-Forwarded-For}i)s %(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
loglevel = "warning"
capture_output = True
