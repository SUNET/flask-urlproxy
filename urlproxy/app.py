# -*- coding: utf-8 -*-
__author__ = 'pettai'

import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from os import environ
from pprint import pformat
from typing import Optional
from urllib import parse as url_parse

import dns.resolver
import elasticsearch
import geoip2.database
import yaml
from elasticsearch import Elasticsearch
from flask import Flask, render_template, request, redirect
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


class UrlProxyApp(Flask):
    def __init__(self, *args, **kwargs):
        self.city_db = kwargs.pop('city_db')
        self.asn_db = kwargs.pop('asn_db')
        super().__init__(*args, **kwargs)


# Init geoip dbs
city_reader = geoip2.database.Reader('/opt/flask-urlproxy/data/GeoLite2-City.mmdb')
asn_reader = geoip2.database.Reader('/opt/flask-urlproxy/data/GeoLite2-ASN.mmdb')

app = UrlProxyApp(__name__, city_db=city_reader, asn_db=asn_reader)
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


@dataclass
class URLProxyContext:
    url: str
    user: Optional[str]
    msgid: str
    fqdn: str
    date: Optional[datetime]
    u_country: str = ''
    u_city: str = ''
    u_asn: str = ''
    u_asnname: str = ''
    s_country: str = ''
    s_city: str = ''
    s_asn: str = ''
    s_asnname: str = ''
    ptr: str = ''
    sender: str = ''
    senderip: str = ''
    ownerdomain: str = ''
    ipv4: str = ''


@app.route('/', methods=['GET'])
@limiter.limit(rate_limit_from_config)
def urlproxy() -> str:
    rfc3986url = request.args.get('url')
    user = request.args.get('rcpt')
    tss = request.args.get('tss')
    msgid = request.args.get('msgid')

    if rfc3986url is None or tss is None or msgid is None:
        return render_template('index.html', title='No Data')

    url = url_parse.unquote(rfc3986url)
    context = URLProxyContext(
        url=url, user=user, msgid=msgid, fqdn=url_parse.urlparse(url).netloc, date=datetime.utcfromtimestamp(int(tss))
    )
    try:
        es = Elasticsearch(
            config.get('ES_ENDPOINT'), use_ssl=True, verify_certs=config.get('ES_VERIFYCERT'), ssl_show_warn=False
        )
        querystring = f"messageid: {msgid}"
        body = {
            'query': {'query_string': {'query': querystring}},
            'fields': ['sender', 'senderip', 'ownerdomain'],
            '_source': 'false',
        }
        response = es.search(body=body, index='halonlog-*')
        app.logger.debug(f'response {pformat(response)}')
    except elasticsearch.exceptions.ConnectionError:
        app.logger.error('Elasticsearch ConnectionError: ES offline?')
        return render_template('index.html', title='No Data')

    if response['hits']['total']['value'] == 1:
        for doc in response['hits']['hits']:
            context.sender = doc["fields"]["sender"][0]
            context.senderip = doc["fields"]["senderip"][0]
            context.ownerdomain = doc["fields"]["ownerdomain"][0]
            # check city db
            city_response = app.city_db.city(context.senderip)
            context.s_country = city_response.country.name
            context.s_city = city_response.city.name
            # check asn db
            asn_response = app.asn_db.asn(context.senderip)
            context.s_asn = asn_response.autonomous_system_number
            context.s_asnname = asn_response.autonomous_system_organization

        if context.senderip:
            try:
                answers = dns.resolver.resolve_address(context.senderip)
                for answer in answers:
                    context.ptr = answer.to_text()
            except dns.resolver.NXDOMAIN:
                context.ptr = 'NXDOMAIN'
                app.logger.debug('%s generated NXDOMAIN', context.senderip)
            except dns.exception.DNSException:
                context.ptr = 'SERVFAIL'
                app.logger.debug('%s generated SERVFAIL', context.senderip)

        try:
            answers = dns.resolver.resolve(context.fqdn, 'A')
            for answer in answers:
                context.ipv4 = answer.to_text()
                # check city db
                city_response = app.city_db.city(context.ipv4)
                context.u_country = city_response.country.name
                context.u_city = city_response.city.name
                # check asn db
                asn_response = app.asn_db.asn(context.ipv4)
                context.u_asn = asn_response.autonomous_system_number
                context.u_asnname = asn_response.autonomous_system_organization
        except dns.resolver.NXDOMAIN:
            context.ipv4 = 'NXDOMAIN'
            app.logger.debug('%s generated NXDOMAIN', context.fqdn)
        except dns.exception.DNSException:
            context.ipv4 = 'SERVFAIL'
            app.logger.debug('%s generated SERVFAIL', context.fqdn)
        return render_template('index.jinja2', title='Halon', **asdict(context))
    return render_template('index.html', title='No Data')

@app.route('/<string:msgid>', methods=['POST'])
@limiter.limit(rate_limit_from_config)
def continue_to_url(msgid) -> str:
    rfc3986url = request.form.get('url')
    app.logger.debug(request.form)
    if not rfc3986url or not msgid:
        return render_template('index.html', title='No Data')

    try:
        es = Elasticsearch(
            config.get('ES_ENDPOINT'), use_ssl=True, verify_certs=config.get('ES_VERIFYCERT'), ssl_show_warn=False
        )
        querystring = f"messageid: {msgid}"
        body = {
            'query': {'query_string': {'query': querystring}},
            'fields': ['messageid'],
            '_source': 'false',
        }
        response = es.search(body=body, index='halonlog-*')
        app.logger.debug(f'response {pformat(response)}')
    except elasticsearch.exceptions.ConnectionError:
        app.logger.error('Elasticsearch ConnectionError: ES offline?')
        return render_template('index.html', title='No Data')

    if response['hits']['total']['value'] == 1:
        return redirect(rfc3986url)
