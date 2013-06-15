#!/usr/bin/python

import os
import sys
import json
from urllib import urlopen

domain = 'yoyoyo.fr'

result = str(urlopen('http://dynette-dev.herokuapp.com/all').read())
result = json.loads(result)

lines = [
        'zone "'+ domain +'" {',
        '   type master;',
        '   file "/var/named/data/yoyoyo.fr.db"; ',
        '   update-policy {',
]

for entry in result:
    fqdn = entry['subdomain'] +'.'+ domain +'.'
    lines.extend([
        '       grant '+ fqdn +' name '+ fqdn +' A TXT;',
        '       grant '+ fqdn +' name pubsub.'+ fqdn +' A;',
        '       grant '+ fqdn +' name muc.'+ fqdn +' A;',
        '       grant '+ fqdn +' name vjud.'+ fqdn +' A;',
        '       grant '+ fqdn +' name _xmpp-client._tcp.'+ fqdn +' SRV;',
        '       grant '+ fqdn +' name _xmpp-server._tcp.'+ fqdn +' SRV;',
    ])

lines.extend([
        '   };',
        '};',
])

for entry in result:
    fqdn = entry['subdomain'] +'.'+ domain +'.'
    lines.extend([
        'key '+ fqdn +' {',
        '       algorithm hmac-md5;',
        '       secret "'+ entry['public_key'] +'";',
        '};',
    ])


with open('/etc/bind/named.conf.local', 'w') as zone:
    for line in lines:
        zone.write(line + '\n')

os.system('rndc reload')
