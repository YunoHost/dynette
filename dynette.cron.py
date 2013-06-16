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
	if not os.path.exists('/var/named/data/'+ domain +'.db'):
            db_lines = [
                '$ORIGIN .',
                '$TTL 10 ; 10 seconds',
                domain+'.   IN SOA  dynhost.yunohost.org hostmaster.yunohost.org. (',
                '                                18         ; serial',
                '                                10800      ; refresh (3 hours)',
                '                                3600       ; retry (1 hour)',
                '                                604800     ; expire (1 week)',
                '                                10         ; minimum (10 seconds)',
                '                                )',
                '$TTL 3600       ; 1 hour',
                '                        NS      dynhost.yunohost.org.',
                '                        NS      hostmaster.yunohost.org.',
                '',
                '$ORIGIN '+ domain +'.',
            ]
            with open('/var/named/data/'+ domain +'.db', 'w') as zone:
                for line in db_lines:
                    zone.write(line + '\n')
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

os.system('chown -R bind:bind /var/named /etc/bind/named.conf.local')
if os.system('rndc reload') == 0:
    exit(0)
else:
    os.system('cp /etc/bind/named.conf.local /etc/bind/named.conf.local.bad')
    os.system('cp /etc/bind/named.conf.back /etc/bind/named.conf.local')
    os.system('rndc reload')
    print("An error occured ! Please check daemon.log and your conf.bad")
    exit(1)
