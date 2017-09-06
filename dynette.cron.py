#!/usr/bin/python

### Configuration ###

conf_file = '/etc/bind/named.conf.local'    # Include this filename in '/etc/bind/named.conf'
zone_dir  = '/var/lib/bind/'                # Do not forget the trailing '/'
subs_urls = ['https://dyndns.yunohost.org']  # 127.0.0.1 if you install subscribe server locally
ns0       = 'ns0.yunohost.org'          # Name servers
ns1       = 'ns1.yunohost.org'
rname     = 'hostmaster@yunohost.org' # Responsible person (https://tools.ietf.org/html/rfc1035#section-3.3.13)

allowed_operations = {
            '.'                  : ['A', 'AAAA', 'TXT', 'MX'],
            '*.'                 : ['A', 'AAAA'],
            'pubsub.'            : ['A', 'AAAA', 'CNAME'],
            'muc.'               : ['A', 'AAAA', 'CNAME'],
            'vjud.'              : ['A', 'AAAA', 'CNAME'],
            '_xmpp-client._tcp.' : ['SRV'],
            '_xmpp-server._tcp.' : ['SRV'],
            'mail._domainkey.'   : ['TXT'],
            '_dmarc.'            : ['TXT']
}


### Script ###

import os
import json
from urllib import urlopen

# Get master key
master_key_path = os.path.join(os.path.dirname(__file__), 'master.key')
master_key = open(master_key_path).read().rstrip()

# Bind configuration
lines = ['// Generated by Dynette CRON']

# Loop through Dynette servers
for url in subs_urls:

    lines.extend([
            'key dynette. {',
            '       algorithm hmac-md5;',
            '       secret "'+ master_key +'";',
            '};',
    ])

    # Get available DynDNS domains
    domains = json.loads(str(urlopen(url +'/domains').read()))
    for domain in domains:

        # Create zone database if not present
        if not os.path.exists(zone_dir + domain +'.db'):
            db_lines = [
                '$ORIGIN .',
                '$TTL 10 ; 10 seconds',
                domain+'.   IN SOA  '+ ns0 +'. '+ rname +'. (',
                '                                18         ; serial',
                '                                10800      ; refresh (3 hours)',
                '                                3600       ; retry (1 hour)',
                '                                604800     ; expire (1 week)',
                '                                10         ; minimum (10 seconds)',
                '                                )',
                '$TTL 3600       ; 1 hour',
                '                        NS      '+ ns0 +'.',
                '                        NS      '+ ns1 +'.',
                '',
                '$ORIGIN '+ domain +'.',
            ]
            with open(zone_dir + domain +'.db', 'w') as zone:
                for line in db_lines:
                    zone.write(line + '\n')

        lines.extend([
                'zone "'+ domain +'" {',
                '   type master;',
                '   file "'+ zone_dir + domain +'.db"; ',
                '   update-policy {',
                '       grant dynette. wildcard *.'+ domain +'. ANY;',
        ])

        # Get registered sub-domains
        result = json.loads(str(urlopen(url +'/all/'+ domain).read()))
        for entry in result:
            for subd, type in allowed_operations.items():
                if subd == '.': subd = ''
                lines.append('       grant '+ entry['subdomain'] +'. name '+ subd + entry['subdomain'] +'. ' + ' '.join(type) +';')

        lines.extend([
                '   };',
                '};'
                '',
        ])

        for entry in result:
            lines.extend([
                'key '+ entry['subdomain'] +'. {',
                '       algorithm ' + entry['key_algo'] + ';',
                '       secret "'+ entry['public_key'] +'";',
                '};',
            ])

# Backup old Bind configuration file.
os.system('cp '+ conf_file +' '+ conf_file +'.back')

# Write Bind configuration file.
with open(conf_file, 'w') as zone:
    zone.write('\n'.join(lines) + '\n')

# Restore ownership
os.system('chown -R bind:bind '+ zone_dir +' '+ conf_file)

# Reload Bind
if os.system('/usr/sbin/rndc reload') == 0:
    exit(0)
else:
    os.system('cp '+ conf_file +' '+ conf_file +'.bad')
    os.system('cp '+ conf_file +'.back '+ conf_file)
    os.system('/usr/sbin/rndc reload')
    print("An error occured ! Please check daemon.log and your conf.bad")
    exit(1)
