#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import multiprocessing.dummy
import requests
import threading
import types
try:
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import parse_qs
import webbrowser
from wsgiref.simple_server import make_server


logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())


def clean_default_arg(arg):
    if arg is False or arg is True or arg is None:
        return arg
    try:
        float(arg)
        return arg
    except ValueError:
        pass
    return '"%s"' % arg


def prompt():
    try:
        from IPython import embed
        embed()
    except ImportError:
        ## this doesn't quite work right, in that it doesn't go to the right env
        ## so we just fail.
        import code
        import rlcompleter
        import readline
        readline.parse_and_bind("tab: complete")
        # calling this with globals ensures we can see the environment
        shell = code.InteractiveConsole(globals())
        shell.interact()


SERVICES = [
    'POSS3',
    'STATS',
    'KEY',
    'ADMINRIGHT',
    'BLOCKED',
    'GESARTICLE',
    'RELOAD',
    'MYACCOUNT',
    'TRANSFER',
    'WEBSALE',
    'WEBSALECONFIRM',
    'MESSAGES',
]


class Service:
    def __init__(self, name, client):
        self.name = name
        self.client = client
        methods = self.call('getMethods')
        for method in methods:
            self._add_method(method)

    def call(self, method, **kw):
        return self.client.call(self.name, method, **kw)

    def _add_method(self, method_definition):
        parameters = method_definition['parameters']
        parameters.sort(key=lambda p: 'default' in p)
        func_parameters = (p['name'] if 'default' not in p else '%s=%s' % (p['name'], clean_default_arg(p['default']))
            for p in parameters)
        call_parameters = ('{0}={0}'.format(p['name']) for p in parameters)
        code = 'def f(self, {func_parameters}): return self.call("{method}", {call_parameters})'
        code = code.format(
            func_parameters=','.join(func_parameters),
            method=method_definition['name'],
            call_parameters=','.join(call_parameters))
        logger.debug('%s => %s' % (method_definition['name'], code))
        d = self.__exec(code)
        d['f'].__doc__ = method_definition['comment']
        f = types.MethodType(d['f'], self)
        setattr(self, method_definition['name'], f)

    def __exec(self, code):
        d = {}
        exec(code, d)
        return d


class Client:
    def __init__(self, location, services=None):
        self.location = location.strip('/')
        self.session = requests.Session()
        if services is None:
            services = SERVICES
        p = multiprocessing.dummy.Pool(len(services))
        p.map(self.add_service, services)
        self.services = services
        self.cas_ticket = None
        self.wsgi_port = 9175
        self.httpd = None
        for _ in range(10000):
            try:
                self.httpd = make_server('', self.wsgi_port, self.wsgi_app)
                break
            except OSError as ex:
                if ex.errno == 98: # address already in use
                    self.wsgi_port += 1
                else:
                    raise
        else:
            Exception('Cannot launch wsgi server')
        self.wsgi_thread = threading.Thread(target=self.httpd.handle_request)
        self.wsgi_thread.daemon = True
        self.wsgi_thread.start()
        self.wsgi_event = threading.Event()

    def add_service(self, service):
        setattr(self, service, Service(service, self))
        logger.info("%s is ready", service)

    def call(self, service__, method, **kw):
        url = '/'.join((self.location, service__, method))
        r = self.session.post(url, data=kw)
        return r.json()

    def wsgi_app(self, environ, start_response):
        if environ['PATH_INFO'] != '/cas':
            start_response('404 NOT FOUND', [('Content-type', 'text/plain')])
            return [b'']
        parameters = parse_qs(environ['QUERY_STRING'])
        ticket = parameters['ticket'][0]
        self.cas_ticket = ticket
        self.wsgi_event.set()
        r = ('Got ticket %s, you can go back to the cli' % ticket)
        start_response('200 OK', [('Content-type', 'text/plain')])
        return [r.encode('utf8')]

    def get_cas_ticket(self, cas_url, timeout=30):
        self.wsgi_event.clear()
        webbrowser.open(cas_url + "login?service=http://localhost:%s/cas" % self.wsgi_port)
        self.wsgi_event.wait(timeout=timeout)
        return self.cas_ticket

    def loginCas(self, service=None, cas_url=None):
        if service is None:
            service = self.services[0]
        service = getattr(self, service)
        if cas_url is None:
            cas_url = service.getCasUrl()
        ticket = self.get_cas_ticket(cas_url)
        return service.loginCas(ticket=ticket, service="http://localhost:%s/cas" % self.wsgi_port)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Connect to payutc server.')
    parser.add_argument('-l', '--location', help='the server url', default='http://localhost/payutc/server/web')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', action="store_true")
    parser.add_argument('-vv', '--verbose_plus',help='Increase verbosity', action="store_true")

    args = parser.parse_args()
    if args.verbose_plus:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)

    client = Client(args.location)
    prompt()
