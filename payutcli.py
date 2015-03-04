#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import logging
import multiprocessing.dummy
import requests
import threading
import types
try:
    from urlparse import parse_qs, parse_qsl, urlsplit, urlunsplit, urlencoded
except ImportError:
    from urllib.parse import parse_qs, parse_qsl, urlsplit, urlunsplit, urlencode
import webbrowser
from wsgiref.simple_server import make_server


logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())


def append_query_parameter(url, name, value):
    """Add the query string parameter 'name=value' to the given url.

    Ex:
        - ('/return', 'id', 42) -> '/return?id=42'
        - ('/return?foo=bar', 'id', 42) -> '/return?foo=bar&id=42'
    """
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_params = parse_qsl(query_string)
    query_params.append((name, value))
    new_query_string = urlencode(query_params, doseq=True)
    return urlunsplit((scheme, netloc, path, new_query_string, fragment))


class PayutcError(Exception):
    def __init__(self, message, code, type, data=None):
        super(PayutcError, self).__init__(message, code, type, data)
        self.message = message
        self.code = code
        self.type = type
        self.data = data


class Client(object):
    def __init__(self, location, insecure=False, timeout=None, ssl_certificate=None, send_json=False, 
        app_key=None, system_id=None, proxies=None):
        """
        :param location: Server location
        :param insecure: Do not check ssl certificate (default: False, meaning secure mode enabled)
        :param timeout: Http timeout (default: no-timeout)
        :param ssl_certificate: Path to ssl certificate
        :send_json: Send json instead of form-urlencoded (default: False)
        :app_key: Send tha app_key to avoid use loginApp
        :system_id: Add a parameter with system_id (for nemopay api)
        :proxies: To set a proxy, put a dict like {'https': 'foo.bar:3128'}
        """
        self.location = location.strip('/')
        self.insecure = insecure
        self.ssl_certificate = ssl_certificate
        self.session = requests.Session()
        self.session.proxies = proxies
        self.timeout = None if timeout is None else float(timeout)
        self.send_json = send_json
        self.app_key = app_key
        self.system_id = system_id

    def call(self, service__, method, **kw):
        """service will be present in the kwargs, so we should call the service argument service__.
        Try to remove it and call loginCas to see the bug :)
        """
        url = '/'.join((self.location, service__, method))

        if self.insecure:
            verify = False
        elif self.ssl_certificate:
            verify = self.ssl_certificate
        else:
            verify = True

        if self.app_key:
            url = append_query_parameter(url, 'app_key', self.app_key)

        if self.system_id:
            url = append_query_parameter(url, 'system_id', self.system_id)

        if self.send_json:
            headers = {'content-type': 'application/json'}
            data = json.dumps(kw)
        else:
            headers = {}
            data = kw

        try:
            r = self.session.post(url, data=data, verify=verify, timeout=self.timeout, headers=headers)
        except requests.exceptions.SSLError as e:
            if 'certificate' in str(e):
                print(e)
                print("Use -k or --insecure to skip ssl certificate check")
            raise
        try:
            r = r.json()
        except Exception as e:
            logger.exception("Error when parsing result for %s.%s" % (service__, method))
            r = {
                'error': {
                    'type': 'JsonDecodeError',
                    'message': "Error during parsing : %r" % r.text,
                    'code': -1,
                }
            }
        if isinstance(r, dict) and 'error' in r:
            if isinstance(r['error'], dict):
                raise PayutcError(**r['error'])
            else:
                raise PayutcError(r['error'], 600, 'WeirdError')
        return r


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
        import rlcompleter  # NOQA
        import readline
        readline.parse_and_bind("tab: complete")
        # calling this with globals ensures we can see the environment
        shell = code.InteractiveConsole(globals())
        shell.interact()


SERVICES = [
    'AUTH',
    'POSS3',
    'STATS',
    'KEY',
    'ADMINRIGHT',
    'BLOCKED',
    'GESARTICLE',
    'RELOAD',
    'MYACCOUNT',
    'MYACCOUNTEXT',
    'TRANSFER',
    'WEBSALE',
    'WEBSALECONFIRM',
    'MESSAGES',
    'SELFPOS',
    'TRESO',
]


class Service:
    def __init__(self, name, client):
        self.name = name
        self.client = client

    def reload(self):
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


class CliClient(Client):
    def __init__(self, location, services=None, insecure=False, ssl_certificate=None, send_json=False,
                 system_id=None, app_key=None):
        super(CliClient, self).__init__(location, insecure=insecure, ssl_certificate=ssl_certificate,
                                        send_json=send_json, system_id=system_id, app_key=app_key)

        if services is None:
            services = SERVICES

        def add_service(service):
            try:
                self.add_service(service)
            except (ValueError, PayutcError) as ex:
                logger.exception(ex)

        p = multiprocessing.dummy.Pool(len(services))
        p.map(add_service, services)
        self.services = services
        self.cas_ticket = None
        self.wsgi_port = 9175
        self.httpd = None
        for _ in range(10000):
            try:
                self.httpd = make_server('', self.wsgi_port, self.wsgi_app)
                break
            except OSError as ex:
                if ex.errno in (48, 98):  # address already in use
                    self.wsgi_port += 1
                else:
                    raise
        else:
            raise Exception('Cannot launch wsgi server')
        self.wsgi_thread = threading.Thread(target=self.httpd.handle_request)
        self.wsgi_thread.daemon = True
        self.wsgi_thread.start()
        self.wsgi_event = threading.Event()
        #self.reload()

    def reload(self):
        for service in self.services:
            getattr(self, service).reload()

    def add_service(self, service):
        setattr(self, service, Service(service, self))
        logger.info("%s is ready", service)

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
            cas_url = service.call('getCasUrl')
        ticket = self.get_cas_ticket(cas_url)
        return service.call('loginCas', ticket=ticket, service="http://localhost:%s/cas" % self.wsgi_port)


def main():
    global client
    import argparse

    parser = argparse.ArgumentParser(description='Connect to payutc server.')
    parser.add_argument('-l', '--location', help='the server url', default='http://localhost/payutc/server/web')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', action="store_true")
    parser.add_argument('-vv', '--verbose_plus', help='Increase verbosity', action="store_true")
    parser.add_argument('-k', '--insecure', help='deactivate ssl check', action="store_true")
    parser.add_argument('-c', '--cert', help='path to the ssl certificate')
    parser.add_argument('-S', '--system-id', help='System id')
    parser.add_argument('-A', '--app-key', help='Application key')
    parser.add_argument('--form-urlencoded', help='use form-urlencoded content-type', action="store_true")

    args = parser.parse_args()
    if args.verbose_plus:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)

    client = CliClient(args.location, insecure=args.insecure, ssl_certificate=args.cert,
                       send_json=not args.form_urlencoded, system_id=args.system_id,
                       app_key=args.app_key)
    prompt()


if __name__ == '__main__':
    main()
