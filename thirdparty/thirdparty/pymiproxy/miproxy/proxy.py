#!/usr/bin/env python
'''
    Forked from version downloaded on 2014-03-13.
    Changes
        2014-10-19  Added X509Extension "authorityKeyIdentifier"
        2014-05-02  Add log
        2014-03-13: Store certificate and key in different files
                    Do not send private key to client
                    Key size increased to 4096
                    Name of certificate as param
                    Timeout as global var
                    
    Last modified: 2014-10-23
'''
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse, urlunparse, ParseResult
from SocketServer import ThreadingMixIn
from httplib import HTTPResponse
from tempfile import gettempdir
from os import chmod, path, listdir
from ssl import wrap_socket
from socket import socket
from re import compile
from sys import argv
from traceback import format_exc

from OpenSSL.crypto import (X509Extension, X509, dump_privatekey, dump_certificate, load_certificate, load_privatekey,
                            PKey, TYPE_RSA, X509Req)
from OpenSSL.SSL import FILETYPE_PEM

from syr.log import get_log
log = get_log()

__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PyMiProxy Project'
__credits__ = ['Nadeem Douba']

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'

__all__ = [
    'CertificateAuthority',
    'ProxyHandler',
    'RequestInterceptorPlugin',
    'ResponseInterceptorPlugin',
    'MitmProxy',
    'AsyncMitmProxy',
    'InvalidInterceptorPluginException'
]

KEY_EXT = '.key'
CERT_SUFFIX = '.pem'
DEFAULT_CA_NAME = 'ca.mitm.com'
DEFAULT_CA_FILE = 'ca{}'.format(CERT_SUFFIX)
TEMP_CERT_PREFIX = '.pymp_'

connect_timeout = 60 # seconds

class CertificateAuthority(object):

    def __init__(self, ca_name=None, ca_file=None, cache_dir=None):
        self.ca_name = ca_name or DEFAULT_CA_NAME
        self.ca_file = ca_file or DEFAULT_CA_FILE
        self.cache_dir = cache_dir or gettempdir()
        self._serial = self._get_serial()
        if path.exists(self.ca_file):
            self.cert, self.key = self._read_ca(self.ca_file)
        else:
            self._generate_ca()

    def _get_serial(self):
        ''' Get the serial number for the website's certificate. '''
        s = 1
        for c in filter(lambda x: x.startswith(TEMP_CERT_PREFIX) and x.endswith(CERT_SUFFIX), listdir(self.cache_dir)):
            c = load_certificate(FILETYPE_PEM, open(path.sep.join([self.cache_dir, c])).read())
            sc = c.get_serial_number()
            if sc > s:
                s = sc
            del c
        return s

    def _generate_ca(self):
        # Generate key
        self.key = self._gen_key()

        # Generate certificate
        self.cert = X509()
        self.cert.set_version(3)
        self.cert.set_serial_number(1)
        self.cert.get_subject().CN = self.ca_name
        self.cert.gmtime_adj_notBefore(0)
        self.cert.gmtime_adj_notAfter(315360000)
        self.cert.set_issuer(self.cert.get_subject())
        self.cert.set_pubkey(self.key)
        self.cert.add_extensions([
            X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
            X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
            X509Extension("subjectKeyIdentifier", False, "hash", subject=self.cert),
            ])
        """
        # the subjectKeyIdentifier must be set before calculating the authorityKeyIdentifier
        self.cert.add_extensions([
            X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=self.cert),
            ])
        """
        self.cert.sign(self.key, "sha1")

        self.write_ca(self.ca_file, self.cert, self.key)
        log.debug('wrote ca cert to {}'.format(self.ca_file))
 
    def _gen_key(self):
        # Generate key
        key = PKey()
        key.generate_key(TYPE_RSA, 4096)
        
        return key

    def _read_ca(self, file):
        cert = load_certificate(FILETYPE_PEM, open(file).read())
        key = load_privatekey(FILETYPE_PEM, open(file+KEY_EXT).read())
        
        return cert, key

    def write_ca(self, cert_file, cert, key):
        ''' Write the certificate and key in separate files for security. '''

        with open(cert_file, 'wb+') as f:
            f.write(dump_certificate(FILETYPE_PEM, cert))
        chmod(cert_file, 0644)
        with open(cert_file+KEY_EXT, 'wb+') as f:
            f.write(dump_privatekey(FILETYPE_PEM, key))
        chmod(cert_file+KEY_EXT, 0600)

    def __getitem__(self, cn):
        cnp = path.sep.join([self.cache_dir, '{}{}{}'.format(TEMP_CERT_PREFIX, cn, CERT_SUFFIX)])
        if not path.exists(cnp):
            # create certificate
            key = self._gen_key()

            # Generate CSR
            req = X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(key)
            req.sign(key, 'sha1')

            # Sign CSR
            cert = X509()
            cert.set_subject(req.get_subject())
            cert.set_serial_number(self.serial)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(31536000)
            cert.set_issuer(self.cert.get_subject())
            cert.set_pubkey(req.get_pubkey())
            cert.sign(self.key, 'sha1')

            # the remote website's certificate and key must be stored together in a temporary file
            with open(cnp, 'wb+') as f:
                f.write(dump_certificate(FILETYPE_PEM, cert))
                f.write(dump_privatekey(FILETYPE_PEM, key))

        return cnp

    @property
    def serial(self):
        self._serial += 1
        return self._serial


class UnsupportedSchemeException(Exception):
    pass


class ProxyHandler(BaseHTTPRequestHandler):

    r = compile(r'http://[^/]+(/?.*)(?i)')

    def __init__(self, request, client_address, server):
        self.is_connect = False
        try:
            BaseHTTPRequestHandler.__init__(self, request, client_address, server)
        except Exception as exc:
            log.debug(format_exc())
            print(exc)
            raise exc

    def _connect_to_host(self):
        # Get hostname and port to connect to
        if self.is_connect:
            self.hostname, self.port = self.path.split(':')
        else:
            u = urlparse(self.path)
            if u.scheme != 'http':
                raise UnsupportedSchemeException('Unknown scheme %s' % repr(u.scheme))
            self.hostname = u.hostname
            self.port = u.port or 80
            self.path = urlunparse(
                ParseResult(
                    scheme='',
                    netloc='',
                    params=u.params,
                    path=u.path or '/',
                    query=u.query,
                    fragment=u.fragment
                )
            )

        # Connect to destination
        self._proxy_sock = socket()
        self._proxy_sock.settimeout(connect_timeout)
        self._proxy_sock.connect((self.hostname, int(self.port)))

        # Wrap socket if SSL is required
        if self.is_connect:
            self._proxy_sock = wrap_socket(self._proxy_sock)


    def _transition_to_ssl(self):
        self.request = wrap_socket(self.request, server_side=True, certfile=self.server.ca[self.path.split(':')[0]])


    def do_CONNECT(self):
        self.is_connect = True
        try:
            # Connect to destination first
            self._connect_to_host()

            # If successful, let's do this!
            self.send_response(200, 'Connection established')
            self.end_headers()
            #self.request.sendall('%s 200 Connection established\r\n\r\n' % self.request_version)
            self._transition_to_ssl()
        except Exception, e:
            self.send_error(500, str(e))
            return

        # Reload!
        self.setup()
        self.ssl_host = 'https://%s' % self.path
        try:
            self.handle_one_request()
        except Exception as exc:
            log.debug(format_exc())
            print(exc)
            raise exc

    def do_COMMAND(self):

        # Is this an SSL tunnel?
        if not self.is_connect:
            try:
                # Connect to destination
                self._connect_to_host()
            except Exception, e:
                self.send_error(500, str(e))
                return
            # Extract path

        # Build request
        req = '%s %s %s\r\n' % (self.command, self.path, self.request_version)

        # Add headers to the request
        req += '%s\r\n' % self.headers

        # Append message body if present to the request
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        # Send it down the pipe!
        self._proxy_sock.sendall(self.mitm_request(req))

        # Parse response
        h = HTTPResponse(self._proxy_sock)
        h.begin()

        # Get rid of the pesky header
        del h.msg['Transfer-Encoding']

        # Time to relay the message across
        res = '%s %s %s\r\n' % (self.request_version, h.status, h.reason)
        res += '%s\r\n' % h.msg
        res += h.read()

        # Let's close off the remote end
        h.close()
        self._proxy_sock.close()

        # Relay the message
        self.request.sendall(self.mitm_response(res))

    def mitm_request(self, data):
        for p in self.server._req_plugins:
            data = p(self.server, self).do_request(data)
        return data

    def mitm_response(self, data):
        for p in self.server._res_plugins:
            data = p(self.server, self).do_response(data)
        return data

    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_COMMAND


class InterceptorPlugin(object):

    def __init__(self, server, msg):
        self.server = server
        self.message = msg


class RequestInterceptorPlugin(InterceptorPlugin):

    def do_request(self, data):
        return data


class ResponseInterceptorPlugin(InterceptorPlugin):

    def do_response(self, data):
        return data


class InvalidInterceptorPluginException(Exception):
    pass


class MitmProxy(HTTPServer):

    def __init__(self, server_address=('', 8080), 
        RequestHandlerClass=ProxyHandler, bind_and_activate=True, 
        ca_name=None, ca_file=None):

        HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.ca = CertificateAuthority(ca_name=ca_name, ca_file=ca_file)
        self._res_plugins = []
        self._req_plugins = []

    def register_interceptor(self, interceptor_class):
        if not issubclass(interceptor_class, InterceptorPlugin):
            raise InvalidInterceptorPluginException('Expected type InterceptorPlugin got %s instead' % type(interceptor_class))
        if issubclass(interceptor_class, RequestInterceptorPlugin):
            self._req_plugins.append(interceptor_class)
        if issubclass(interceptor_class, ResponseInterceptorPlugin):
            self._res_plugins.append(interceptor_class)


class AsyncMitmProxy(ThreadingMixIn, MitmProxy):
    pass


class MitmProxyHandler(ProxyHandler):

    def mitm_request(self, data):
        print '>> %s' % repr(data[:100])
        return data

    def mitm_response(self, data):
        print '<< %s' % repr(data[:100])
        return data


class DebugInterceptor(RequestInterceptorPlugin, ResponseInterceptorPlugin):

        def do_request(self, data):
            print '>> %s' % repr(data[:100])
            return data

        def do_response(self, data):
            print '<< %s' % repr(data[:100])
            return data


if __name__ == '__main__':
    proxy = None
    if not argv[1:]:
        proxy = AsyncMitmProxy()
    else:
        proxy = AsyncMitmProxy(ca_file=argv[1])
    proxy.register_interceptor(DebugInterceptor)
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        proxy.server_close()

