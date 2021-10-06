# -*- coding: utf-8 -*-
__author__ = 'pettai'

import sys
import urllib
from datetime import datetime
from os import environ
from pprint import pprint

import dns.resolver
import geoip2.database
import yaml
from elasticsearch import Elasticsearch
from flask import Flask, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from whitenoise import WhiteNoise

# Read config
config_path = environ.get('URLPROXY_CONFIG', 'config.yaml')
try:
    with open(config_path) as f:
        config = yaml.safe_load(f)
except FileNotFoundError as e:
    print('Set environment variable URLPROXY_CONFIG to config file path')
    print(e)
    sys.exit(1)


app = Flask(__name__)
app.config.from_mapping(config)

# Init logging
app.config.setdefault('LOG_LEVEL', 'INFO')
app.logger.setLevel(app.config['LOG_LEVEL'])
app.logger.info('Setting loglevel to %s', config.get('LOG_LEVEL'))

# Init static files
app.wsgi_app = WhiteNoise(app.wsgi_app, root=config.get('STATIC_FILES', 'urlproxy/static/'))  # type: ignore

# Init rate limiting
limiter = Limiter(app, key_func=get_remote_address)


def rate_limit_from_config():
    return app.config.get('REQUEST_RATE_LIMIT', '1/second')


@app.route('/', methods=['GET'])
@limiter.limit(rate_limit_from_config)
def urlproxy():
    rfc3986url = request.args.get('url')
    user = request.args.get('rcpt')
    tss = request.args.get('tss')
    msgid = request.args.get('msgid')
    if rfc3986url is None or tss is None or msgid is None:
        return render_template('index.html', title='No Data')
    else:
        url = urllib.parse.unquote(rfc3986url)
        fqdn = urllib.parse.urlparse(url).netloc
        date = datetime.utcfromtimestamp(int(tss)).strftime('%Y-%m-%d %H:%M:%S UTC')
        u_country = ''
        u_city = ''
        u_asn = ''
        u_asnname = ''
        s_country = ''
        s_city = ''
        s_asn = ''
        s_asnname = ''
        ptr = ''
        sender = ''
        senderip = ''
        ownerdomain = ''
        try:
            es = Elasticsearch(
                config.get('ES_ENDPOINT'), use_ssl=True, verify_certs=config.get('ES_VERIFYCERT'), ssl_show_warn=False
            )
            querystring = f"messageid: {msgid}".format(msgid)
            body = {
                'query': {'query_string': {'query': querystring}},
                'fields': ['sender', 'senderip', 'ownerdomain'],
                '_source': 'false',
            }
            response = es.search(body, index='halonlog-*')
            app.logger.debug('response %s', (pprint(response)))
            if response['hits']['total']['value'] >= 1:
                for doc in response['hits']['hits']:
                    sender = doc["fields"]["sender"][0]
                    senderip = doc["fields"]["senderip"][0]
                    ownerdomain = doc["fields"]["ownerdomain"][0]
                    with geoip2.database.Reader('/opt/flask-urlproxy/data/GeoLite2-City.mmdb') as reader:
                        response = reader.city(senderip)
                        s_country = response.country.name
                        s_city = response.city.name
                    with geoip2.database.Reader('/opt/flask-urlproxy/data/GeoLite2-ASN.mmdb') as reader:
                        response = reader.asn(senderip)
                        s_asn = response.autonomous_system_number
                        s_asnname = response.autonomous_system_organization
                try:
                    answers = dns.resolver.resolve_address(senderip)
                    for iter in answers:
                        ptr = iter.to_text()
                except dns.resolver.NXDOMAIN:
                    ptr = 'NXDOMAIN'
                    app.logger.debug('%s generated NXDOMAIN', senderip)
                except dns.exception.DNSException:
                    ptr = 'SERVFAIL'
                    app.logger.debug('%s generated SERVFAIL', senderip)

                try:
                    answers = dns.resolver.resolve(fqdn, 'A')
                    for iter in answers:
                        ipv4 = iter.to_text()
                        with geoip2.database.Reader('/opt/flask-urlproxy/data/GeoLite2-City.mmdb') as reader:
                            response = reader.city(ipv4)
                            u_country = response.country.name
                            u_city = response.city.name
                        with geoip2.database.Reader('/opt/flask-urlproxy/data/GeoLite2-ASN.mmdb') as reader:
                            response = reader.asn(ipv4)
                            u_asn = response.autonomous_system_number
                            u_asnname = response.autonomous_system_organization
                except dns.resolver.NXDOMAIN:
                    ipv4 = 'NXDOMAIN'
                    app.logger.debug('%s generated NXDOMAIN', fqdn)
                except dns.exception.DNSException:
                    ipv4 = 'SERVFAIL'
                    app.logger.debug('%s generated SERVFAIL', fqdn)
                return render_template(
                    'index.jinja2',
                    title='Halon',
                    url=(url),
                    fqdn=(fqdn),
                    ipv4=(ipv4),
                    country=(u_country),
                    city=(u_city),
                    asn=(u_asn),
                    asnname=(u_asnname),
                    user=(user),
                    date=(date),
                    msgid=(msgid),
                    sender=(sender),
                    senderip=(senderip),
                    ptr=(ptr),
                    scountry=(s_country),
                    scity=(s_city),
                    sasn=(s_asn),
                    sasnname=(s_asnname),
                    owner=(ownerdomain),
                )

            else:
                return render_template('index.html', title='No Data')

        except elasticsearch.exceptions.ConnectionError:
            app.logger.debug('Elasticsearch ConnectionError: ES offline?')
