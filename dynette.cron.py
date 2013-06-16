#!/usr/bin/python

import os
import sys
import json
from urllib import urlopen

urls = ['http://dynette-dev.herokuapp.com']
lines = []

for url in urls:
    domains = json.loads(str(urlopen(url +'/domains').read()))

    for domain in domains:
        result = json.loads(str(urlopen(url +'/all/'+ domain).read()))
        lines.extend([
                'zone "'+ domain +'" {',
                '   type master;',
                '   file "/var/named/data/'+ domain +'.db"; ',
                '   update-policy {',
        ])

        for entry in result:
            fqdn = entry['subdomain'] +'.'
            lines.extend([
                '       grant '+ fqdn +' name '+ fqdn +' A TXT MX;',
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
            fqdn = entry['subdomain'] +'.'
            lines.extend([
                'key '+ fqdn +' {',
                '       algorithm hmac-md5;',
                '       secret "'+ entry['public_key'] +'";',
                '};',
            ])


os.system('cp /etc/bind/named.conf.local /etc/bind/named.conf.local.back')

with open('/etc/bind/named.conf.local', 'w') as zone:
    for line in lines:
        zone.write(line + '\n')

if os.system('rndc reload') == 0:
    exit(0)
else:
    os.system('cp /etc/bind/named.conf.local /etc/bind/named.conf.local.bad')
    os.system('cp /etc/bind/named.conf.back /etc/bind/named.conf.local')
    os.system('rndc reload')
    print("An error occured ! Please check daemon.log and your conf.bad")
    exit(1)
