#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import requests
import types


logger = logging.getLogger(__name__)


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
        self.cookies = None
        if services is None:
            services = SERVICES
        for service in services:
            setattr(self, service, Service(service, self))
        self.services = services

    def call(self, service, method, **kw):
        url = '/'.join((self.location, service, method))
        r = requests.post(url, data=kw, cookies=self.cookies)
        self.cookies = r.cookies
        return r.json()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Connect to payutc server.')
    parser.add_argument('-l', '--location', help='the server url', default='http://localhost/payutc/server/web')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', action="store_true")

    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    client = Client(args.location)
    prompt()
