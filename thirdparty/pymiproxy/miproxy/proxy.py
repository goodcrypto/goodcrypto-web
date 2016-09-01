#! /usr/bin/python
'''
    Forked from version downloaded on 2014-03-13.

    Last modified: 2016-01-30
'''

import os, socks, ssl, threading, time
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
from httplib import HTTPResponse, BadStatusLine
from re import compile
from socket import socket
from SocketServer import ThreadingMixIn
from sys import argv
from tempfile import gettempdir
from traceback import format_exc
from urlparse import urlparse, urlunparse, ParseResult

from OpenSSL.crypto import (X509, X509Extension, X509Name, dump_privatekey, dump_certificate,
                            load_certificate, load_privatekey, PKey, TYPE_RSA, X509Req)
from OpenSSL.SSL import FILETYPE_PEM

from backports.ssl_match_hostname import match_hostname, CertificateError

from syr import openssl
from syr.utils import randint
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
    'ProxyRequestHandler',
    'RequestInterceptorPlugin',
    'ResponseInterceptorPlugin',
    'MitmProxy',
    'AsyncMitmProxy',
    'InvalidInterceptorPluginException'
]

USE_OPENSSL = True

KEY_EXT = '.key'
CERT_SUFFIX = '.crt'
DEFAULT_CA_NAME = 'ca.mitm.com'
DEFAULT_CA_FILE = 'ca{}'.format(CERT_SUFFIX)
TEMP_CERT_PREFIX = '.pymp_'
GLOBAL_CA_CERTS='/etc/ssl/certs/ca-certificates.crt'

HTTP_NO_SECURE_CONNECTION = 502 # there's no good http result code yet for bad security

DAYS_IN_10_YEARS = 365 * 10
SECONDS_IN_YEAR = 31536000 # 60 * 60 * 24 * 365

connect_timeout = 60 # seconds

def verify_cert(cn):
    ''' Verify the site's certificate. '''

    # Verify the cert is ok before proceeding
    hostname = cn
    log.debug('getting cert for: {}'.format(hostname))
    ok, original_cert, cert_error_details = openssl.verify_certificate(hostname, 443)
    log.debug('{} cert ok: {}'.format(hostname, ok))

    if not ok:
        log.debug(cert_error_details)

        # if the cert is self signed or expired, let the user decide what to do
        if openssl.SELF_SIGNED_CERT_ERR_MSG in cert_error_details:
            log.debug('cert is self.signed')
            ok = True
        elif openssl.EXPIRED_CERT_ERR_MSG in cert_error_details:
            log.debug('cert is expired')
            ok = True

    return ok, original_cert, cert_error_details


class CertificateAuthority(object):

    def __init__(self, ca_name=None, ca_file=None, cache_dir=None, ca_common_name=None, keys_dir=None):
        self.ca_name = ca_name or DEFAULT_CA_NAME
        log.debug('ca organization: {}'.format(self.ca_name))
        self.ca_common_name = ca_common_name or DEFAULT_CA_NAME
        log.debug('ca common name: {}'.format(self.ca_common_name))
        self.ca_file = ca_file or DEFAULT_CA_FILE
        log.debug('ca cert file: {}'.format(self.ca_file))
        self.cache_dir = cache_dir or gettempdir()
        # directory to keep info about sites' keys (e.g., hashes, expiration date)
        self.keys_dir = keys_dir
        self._get_serials()
        if os.path.exists(self.ca_file):
            self.cert, self.key = self._read_ca(self.ca_file)
            self._serials.add(self.cert.get_serial_number())
        else:
            self._generate_ca()

        if not os.path.exists(self.keys_dir):
            os.mkdir(self.keys_dir)
            log.debug('created {}'.format(self.keys_dir))

    def _get_serials(self):
        ''' Get the set of web site serial numbers. '''

        self._serials = set()

        # existing website certificates
        # log.debug('cache dir:\n    {}'.format('\n    '.join(os.listdir(self.cache_dir))))
        for cert_filename in filter(lambda cert_path:
            cert_path.startswith(TEMP_CERT_PREFIX) and cert_path.endswith(CERT_SUFFIX),
            os.listdir(self.cache_dir)):

            cert_path = os.path.join(self.cache_dir, cert_filename)
            log.debug('existing web site cert path {}'.format(cert_path))
            cert = load_certificate(FILETYPE_PEM, open(cert_path).read())
            sc = cert.get_serial_number()
            assert sc not in self._serials
            self._serials.add(sc)
            log.debug('existing web site cert path {} has serial {}'.
                format(cert_path, cert.get_serial_number()))
            del cert

        # ca certs are added to the set separately

    def _generate_ca(self):
        ''' Generate certificate authority's own certificate '''

        if USE_OPENSSL:
            dirname = os.path.dirname(self.ca_file)
            public_cert_name = os.path.basename(self.ca_file)
            private_key_name = '{}{}'.format(public_cert_name, KEY_EXT)

            openssl.generate_certificate(self.ca_common_name, dirname,
              private_key_name=private_key_name, public_cert_name=public_cert_name,
              name=self.ca_name, days=DAYS_IN_10_YEARS)

            # openssl defaults  the private key to a subdirectory
            # some apps, like this one, need it the same level as public certificate
            openssl.move_private_key(dirname, private_key_name)

            self.cert, self.key = self._read_ca(self.ca_file)

        else:
            # Generate key
            self.key = self._gen_key()

            self.cert = X509()
            self.cert.set_version(3)

            self.cert.set_serial_number(self._new_serial())
            self._serials.add(self.cert.get_serial_number())
            log.debug('ca cert has serial {}'.format(self.cert.get_serial_number()))

            #self.cert.get_subject().O = self.ca_common_name
            self.cert.get_subject().CN = self.ca_name
            self.cert.gmtime_adj_notBefore(0)
            self.cert.gmtime_adj_notAfter(SECONDS_IN_YEAR)
            self.cert.set_issuer(self.cert.get_subject())
            self.cert.set_pubkey(self.key)

        self.cert.add_extensions([
            # X509Extension("basicConstraints", True, "CA:TRUE"),
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
        self.cert.sign(self.key, "sha256")

        log.debug('write ca cert to {}'.format(self.ca_file))
        self._write_ca(self.ca_file, self.cert, self.key)

    def _gen_key(self):
        # Generate key
        key = PKey()
        key.generate_key(TYPE_RSA, 4096)

        return key

    def _write_key(self, path, key, permissions):
        ''' Write key to path. '''

        if os.path.exists(path):
            os.remove(path)
        with open(path, 'wb') as f:
            f.write(key)
        os.chmod(path, permissions)

    def _read_ca(self, file):
        ''' Read a ca cert and key from file '''

        cert = load_certificate(FILETYPE_PEM, open(file).read())
        key = load_privatekey(FILETYPE_PEM, open(file+KEY_EXT).read())
        # log.debug('read cert and key from {}'.format(file))

        return cert, key

    def _write_ca(self, cert_file, cert, key):
        ''' Write the certificate and key in separate files for security. '''

        self._write_key(cert_file, dump_certificate(FILETYPE_PEM, cert), 0444)
        self._write_key(cert_file+KEY_EXT, dump_privatekey(FILETYPE_PEM, key), 0400)

    def _create_cert(self, cn, public_cert_name, cert_path):
        ''' Create new site certificate signed by our certificate authority '''
        
        private_key_name = '{}{}'.format(public_cert_name, KEY_EXT)
        key_path = os.path.join(self.cache_dir, private_key_name)

        # self.handle_one_request() already verified the cert
        # We used to say "!!!! Need to verify cert" even after a debian 
        # update handled it.
        # openssl.verify_cert() call is unneeded because
        # self.handle_one_request() verifies the cert, and unwanted until 
        # openssl.verify_cert() goes through tor
        """ We don't use openssl to verify certs until we can make it
            go through tor. Newer openssl versions can use a proxy,
            but not the one in debian jessie. Some options:
                 * install from debian backports
                 * use torsocks or similar
                 * install from source
        """
        ok = True
        cert_error_details = None
        #ok, original_cert, cert_error_details = verify_cert(cn)

        if ok:
            log.debug('generating a cert for {}'.format(cn))
            if USE_OPENSSL:

                openssl.generate_certificate(cn, self.cache_dir,
                  private_key_name=private_key_name, public_cert_name=public_cert_name, days=DAYS_IN_10_YEARS)

                # the private key defaults to a subdirectory so move it to the same level as public certificate
                openssl.move_private_key(self.cache_dir, private_key_name)

                # read the new certificate and key
                cert, key = self._read_ca(os.path.join(self.cache_dir, public_cert_name))
                
                # some browsers (firefox) will reject a cert with a timestamp of now
                time.sleep(5)

            else:
                # create certificate
                key = self._gen_key()

                # Generate CSR
                req = X509Req()
                req.get_subject().CN = cn
                req.set_pubkey(key)
                req.sign(key, 'sha256')

                # Sign CSR
                cert = X509()
                cert.set_subject(req.get_subject())
                cert.set_serial_number(self._new_serial())
                log.debug('web site cert for {} has serial {}'.
                    format(cn, cert.get_serial_number()))
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(SECONDS_IN_YEAR)
                cert.set_pubkey(req.get_pubkey())

            if cert_error_details is None:
                # add the issuer and sign it with our key
                cert.set_issuer(self.cert.get_subject())
                cert.sign(self.key, 'sha256')
                
            else:
                # make browser complain about 'self-signed cert'
                # ideally, we'd like the user to see the original cert_error_details, but that doesn't
                # seem to be working yet so this is better than just accepting the cert
                log.debug('intentionally not signing cert, so that the browser will warn user')

                not_before, not_after = openssl.get_dates(original_cert)
                before_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                after_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                cert.set_notBefore(before_date.strftime('%Y%m%d%H%M%S+0000'))
                cert.set_notAfter(after_date.strftime('%Y%m%d%H%M%S+0000'))

                # don't sign the cert, so the user can decide whether to accept it or not
                #x509Name = X509Name(X509())
                #x509Name.__setattr__('_name', cn)
                #x509Name.__setattr__('issuer', openssl.get_issuer(original_cert))
                #x509Name.__setattr__('subject', openssl.get_issued_to(original_cert))
                #cert.set_issuer(x509Name)
                #cert.set_subject(x509Name)

            log.debug('write {} web site cert to {}'.format(cn, cert_path))
            self._write_key(cert_path, dump_certificate(FILETYPE_PEM, cert), 0400)

            if not USE_OPENSSL:
                log.debug('write {} web site private key to {}'.format(cn, key_path))
                self._write_key(key_path, dump_privatekey(FILETYPE_PEM, key), 0400)

        else:
            log.debug('raising SSL error')
            raise ssl.SSLError(cert_error_details)

        return cert_path

    def _new_serial(self):
        ''' Return an unused serial number '''

        # !! what is the range of a cert serial?
        MAXSERIAL = 1000000000

        s = randint(1, MAXSERIAL)
        while s in self._serials:
            log.debug('serial {} already exists'.format(s))
            s = randint(1, MAXSERIAL)
        self._serials.add(s)

        log.debug('new serial {}'.format(s))

        return s

    def __getitem__(self, cn):
        ''' Return path to site certificate signed by our certificate authority '''
        
        public_cert_name = '{}{}{}'.format(TEMP_CERT_PREFIX, cn, CERT_SUFFIX)
        cert_path = os.path.join(self.cache_dir, public_cert_name)
        
        if not os.path.exists(cert_path):
            cert_path = self._create_cert(cn, public_cert_name, cert_path)
            
        return cert_path
        

class UnsupportedSchemeException(Exception):
    pass


class UnexpectedDisconnectException(Exception):
    pass


class StopRequest(Exception):
    pass
    
    
class ProxyRequestHandler(BaseHTTPRequestHandler):
    ''' Handle a request in the proxy.

        Because we are using ThreadingMixIn, each instance is in its own
        thread. Any shared data outside of this instance must be protected
        by a threading.Lock().
    '''

    lock = threading.Lock()
    request_serial = 0
    r = compile(r'http://[^/]+(/?.*)(?i)')

    def __init__(self, request, client_address, server):

        ProxyRequestHandler.lock.acquire()
        ProxyRequestHandler.request_serial += 1
        self.request_serial = ProxyRequestHandler.request_serial
        self.request_valid = True
        ProxyRequestHandler.lock.release()

        self.is_connect = False
        self.self_signed_cert = False
        
        try:
            BaseHTTPRequestHandler.__init__(self, request, client_address, server)
            
        except StopRequest:
            pass
            
        except Exception as exc:
            log.debug(exc)
            # print(exc)
            raise exc

    def do_CONNECT(self):
        ''' Connect to remote host via https::
                1. Connect to host via unencrypted http, without sending url path.
                2. Check certificate is valid.
                3. Transition to ssl.
                4. Reconnect via ssl and send full url.
                
            The HTTP CONNECT command is a command from the client to the 
            proxy, not to the remote host.

            do_CONNECT() is called when an http CONNECT request is received
            from the client. BaseHTTPRequestHandler.handle_one_request()
            calls getattr(), which calls do_CONNECT().
        '''

        self.is_connect = True
        
        self.log_request_progress('proxy request to {}'.format(self.path))

        if self.request_valid:
            try:
                # Don't send full url unencrypted; wait until we get an https connection
                self.log_request_progress('connect to host using https, but using http first')
                self._connect_to_host()
            except Exception as e:
                self.abort_request(
                    'could not make trial http connection for https connection',
                    e,
                    code=HTTP_NO_SECURE_CONNECTION)
                return
                
        # make connection from this proxy to remote secure
        if self.request_valid:
            self._proxy_sock = self.make_socket_secure(self._proxy_sock)

        # tell client we're connected
        if self.request_valid:
            try:
                self.log_request_progress('send client initial response 200')
                try:
                    self.send_response(200, 'Connection established')
                    #self.request.sendall('%s 200 Connection established\r\n\r\n' % self.request_version)
                    self.end_headers()
                # having trouble with 'Broken pipe'
                # if no trouble with 'Broken pipe' by 2015-09-01, remove this try/except (save the else clause)
                except IOError as ioError:
                    if 'Broken pipe' in str(ioError):
                        self.log_request_progress(
                            "'Broken pipe' trying to send http 200 response to client after initial connection")
                        log.debug(ioError)
                        raise
            except Exception as e:
                self.abort_request(
                    'could not send 200 response to client for https connection',
                    e)
                return

        # make client side https
        if self.request_valid:
            try:
                self.log_request_progress('use https between client and this proxy')
                self._make_request_secure()
            except ssl.SSLError as ssl_error:
                self.abort_request(ssl_error, code=HTTP_NO_SECURE_CONNECTION)
                return
            except Exception as e:
                self.abort_request(
                    'could not use https between client and this proxy',
                    e,
                    code=HTTP_NO_SECURE_CONNECTION)
                return
            else:
                self.log_request_progress('using https between client and this proxy')

        # the http/https without the full url worked, so send the full url
        if self.request_valid:
            self.log_request_progress('restart request as https: {}'.
                format(self.path))
            self.setup()
            self.ssl_host = 'https://%s' % self.path
            try:
                self.log_request_progress('handle one request as https')
                # this is where we detect a bad cert
                self.handle_one_request()

            except ssl.SSLError as ssl_error:
                self.log_request_progress('ssl error while connecting to remote host {}'.
                    format(self.ssl_host))
                log.debug(ssl_error)
                if True: # 'TLSV1_ALERT_UNKNOWN_CA' in str(ssl_error):
                    ok, original_cert, cert_error_details = verify_cert(self.ssl_host)
                    self.abort_request(ssl_error, code=HTTP_NO_SECURE_CONNECTION)
                raise ssl_error

            except Exception as exc:
                self.log_request_progress('error in https connection to remote host {}'.
                    format(self.ssl_host))
                log.debug(exc)
                # print(exc)
                raise exc

            else:
                self.log_request_progress('handled request as https')

    def do_COMMAND(self):
        ''' Send the client's http command to the remote host.

            do_COMMAND() is the default method called when
            BaseHTTPRequestHandler.handle_one_request() receives an HTTP
            request, and no matching do_X() method is defined in this class.
            See __getattr__() in this class.
        '''

        self.log_request_progress('client sent http request {} {}'.
            format(self.command, self.path))

        if self.request_valid:
            # Is this an SSL tunnel?
            if not self.is_connect:
                try:
                    # Connect to destination
                    self._connect_to_host()
                except Exception as exc:
                    self.log_request_progress('unable to connect to host'.
                        format(self.request_serial))
                    log.debug(exc)
                    self.abort_request(exc, code=HTTP_NO_SECURE_CONNECTION)
                    return
                # Extract path

        if self.request_valid:
            # Build request
            req = '%s %s %s\r\n' % (self.command, self.path, self.request_version)

            # Add headers to the request
            req += '%s\r\n' % self.headers

            # Append message body if present to the request
            if 'Content-Length' in self.headers:
                req += self.rfile.read(int(self.headers['Content-Length']))

            # Send it down the pipe!
            self.log_request_progress('send request'.format(self.request_serial))
            self._proxy_sock.sendall(self.mitm_request(req))
            self.log_request_progress('sent request'.format(self.request_serial))

            # Parse response
            self.log_request_progress('get response'.format(self.request_serial))
            h = HTTPResponse(self._proxy_sock)

            try:
                self.log_request_progress('get response header'.format(self.request_serial))
                h.begin()
            except BadStatusLine:
                # to quote httplib:
                # Presumably, the server closed the connection before
                # sending a valid response.
                raise UnexpectedDisconnectException(
                    'Remote host disconnected before sending response. TLS error? (Bad status line)')
            self.log_request_progress('got response header'.format(self.request_serial))

            # Get rid of the pesky header
            del h.msg['Transfer-Encoding']

            # Time to relay the message across
            res = '%s %s %s\r\n' % (self.request_version, h.status, h.reason)
            res += '%s\r\n' % h.msg
            self.log_request_progress('get response content'.format(self.request_serial))
            res += h.read()
            self.log_request_progress('got response content'.format(self.request_serial))

            # Let's close off the remote end
            self.log_request_progress('close remote connection'.format(self.request_serial))
            h.close()
            self._proxy_sock.close()
            self.log_request_progress('closed remote connection'.format(self.request_serial))

            # Relay the message
            self.log_request_progress('send response to client'.format(self.request_serial))
            self.request.sendall(self.mitm_response(res))
            self.log_request_progress('sent response to client'.format(self.request_serial))
            
    def _connect_to_host(self):
        ''' Connect this proxy to remote host. '''
        
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
        self.log_request_progress('connect to {}'.format(self.netloc()))
        self._proxy_sock = socket()
        try:
            self._proxy_sock.settimeout(connect_timeout)
            self._proxy_sock.connect((self.hostname, int(self.port)))
        except socks.Socks5Error as socks_error:
            self.abort_request(socks_error, code=HTTP_NO_SECURE_CONNECTION)
            return
        else:
            self.log_request_progress('{} connected'.format(self.netloc()))

    def _make_request_secure(self):
        ''' Make the socket between the client and this proxy secure. '''
        
        cert_filename = self.server.ca[self.path.split(':')[0]]
        self.request = self.make_socket_secure(
            self.request,
            server_side=True,
            certfile=cert_filename,
            keyfile=cert_filename + KEY_EXT)
                    
    def make_socket_secure(self, insecure_socket, **kwargs):
        ''' Transition trial http socket to https. 
        
            Returns secure socket. If error, returns None and self.request_valid is set to False
        '''
        
        """ NOT WORKING -- fix this!!
        kwargs.update(dict(
            cert_reqs=ssl.CERT_REQUIRED, 
            ca_certs=GLOBAL_CA_CERTS,
        ))
        """

        # in order by preference
        # in python 2.7 SSLv23 tries the same protocols. in the same order?
        ALLOWED_PROTOCOLS = [
            ssl.PROTOCOL_TLSv1_2,
            ssl.PROTOCOL_TLSv1_1,
            ssl.PROTOCOL_TLSv1,
            # ssl.PROTOCOL_SSLv3,
            ]
        PROTOCOL_NAMES = {
            ssl.PROTOCOL_TLSv1_2: 'TLSv1.2',
            ssl.PROTOCOL_TLSv1_1: 'TLSv1.1',
            ssl.PROTOCOL_TLSv1: 'TLSv1',
            # ssl.PROTOCOL_SSLv3: 'SSLv3',
            }
        
        secure_socket = None
        for protocol in ALLOWED_PROTOCOLS:
            if secure_socket is None:
                
                try:
                    kwargs.update(dict(ssl_version=protocol))
                    # ssl.wrap_socket() checks the protocol, but not the cert
                    # we won't know about a bad cert until after we restart 
                    # the request as https
                    secure_socket = ssl.wrap_socket(
                        insecure_socket,
                        **kwargs)
                        
                except ssl.SSLError as ssl_error:
                    if 'WRONG_VERSION_NUMBER' in str(ssl_error):
                        self.log_request_progress('remote host does not support {}'.
                            format(PROTOCOL_NAMES[protocol]))
                    else:
                        self.log_request_progress('ssl error for protocol: {}'.
                            format(PROTOCOL_NAMES[protocol]))
                        log.debug(ssl_error)
                        
                except Exception as exc:
                    self.log_request_progress('{} protocol failed'.
                        format(PROTOCOL_NAMES[protocol]))
                    log.debug(exc)
                    
                else:
                    self.log_request_progress('{} protocol succeeded'.
                        format(PROTOCOL_NAMES[protocol]))
                        
        if secure_socket is None:
            self.abort_request(
                'remote host {} does not support any allowed secure protocol'.
                format(self.netloc()), code=HTTP_NO_SECURE_CONNECTION)
            return
                
        """ NOT WORKING -- fix this!!
        # check host name matches
        if secure_socket:
            try:
                match_hostname(secure_socket.getpeercert(), self.hostname)
            except CertificateError as ce:
                log.debug(ce)
                self.abort_request('Unable to make secure connection to {}'.format(
                    self.netloc()),
                    code=HTTP_NO_SECURE_CONNECTION)
                return
        """
                
        return secure_socket

    def abort_request(self, msg, e=None, code=500):
        ''' Stop request processing. 
        
            Send client 50x error response. Raise StopRequest. 
        '''
        
        self.request_valid = False

        msg = str(msg).strip()
        self.log_request_progress(msg)
        # in case the error wasn't logged earlier
        log.debug('abort_request():\n{}'.format(format_exc().strip()))
        if e is not None:
            log.debug(e)
            
        self.log_request_progress('send 500 error to client: {}'.format(msg))
        try:
            self.send_error(code, msg)
            
        except Exception as exc:
            # if client is no longer listening, just log it
            text = str(exc).strip()
            if 'Broken pipe' in text:
                log.debug('unable to send 500 error to client ({})'.format(type(exc)))
            else:
                log.debug(text)
                raise
                
        # else:
        #     self.log_request_progress('500 error to client sent')
        
        raise StopRequest(msg)
        
    def netloc(self):
        ''' Return netloc. '''
        
        loc = self.hostname
        if self.port != 80:
            loc = loc + ':' + str(self.port)
        return loc

    def mitm_request(self, data):
        for p in self.server._req_plugins:
            data = p(self.server, self).do_request(data)
        return data

    def mitm_response(self, data):
        for p in self.server._res_plugins:
            data = p(self.server, self).do_response(data)
        return data

    def __getattr__(self, item):
        ''' Return self.do_COMMAND, which is the default method for any
            http commands without an explicit do_X method defined in this
            class.

            This function is indirectly called from
            BaseHTTPRequestHandler.handle_one_request().
            When handle_one_request() gets an http request, it parses the
            first line of the request for the http command. Then
            handle_one_request() calls getattr(self, do_ITEM). The ITEM is
            the http command from the request.

            For example, if the http request command is CONNECT,
            handle_one_request() calls getattr(self, 'do_CONNECT') to look
            for a method called 'self.do_CONNECT'. In this case getattr()
            finds a do_CONNECT method in this calls and returns it.
            But if getattr() doesn't find an explicitly defined attribute,
            it calls __getattr__().

            This implementation of __getattr__() always returns
            self.do_COMMAND for any itmes that start with 'do_'. The method
            self.do_COMMAND() is the default method for any http commands
            without an explicit do_X method.
        '''

        if item.startswith('do_'):
            self.log_request_progress('generic http request command: {}'.format(item))
            return self.do_COMMAND
        else:
            msg = '{} has no attribute {}'.format(self, item)
            self.log_request_progress(msg)
            # raise AttributeError(msg)

    def log_request_progress(self, msg):
        ''' Log progress with request serial number '''

        log.debug('{} {}'.format(self.request_serial, msg.strip()))

    def log_message(self, format, *args):
        """ Log an arbitrary message.

            Override BaseHTTPServer.log_message() because the default 
            writes directly to stderr. This can cause a "Broken pipe"
            error if this function is called from a program launched
            via the sh module without explicitly redirecting stderr.
        """

        msg = ('%s - - [%s] %s\n' %
            (self.client_address[0],
            self.log_date_time_string(),
            format % args))
        msg = msg.strip()
        log.debug(msg)

    def finish(self,*args,**kw):
        ''' Finish a request.
        
            Override SocketServer.StreamRequestHandler.finish() to avoid some
            "Broken pipe" errors.

            See exception handling - Python BaseHTTPServer, how do I catch/trap "broken pipe" errors? - Stack Overflow
                http://stackoverflow.com/questions/6063416/python-basehttpserver-how-do-i-catch-trap-broken-pipe-errors
        '''
        try:
            if not self.wfile.closed:
                self.wfile.flush()
                self.wfile.close()
        except Exception as exc:
            # it probably doesn't matter
            if not 'Broken pipe' in str(exc):
                log.debug(exc)
        self.rfile.close()

        #Don't call the base class finish() method as it does the above
        #return SocketServer.StreamRequestHandler.finish(self)

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
        RequestHandlerClass=ProxyRequestHandler, bind_and_activate=True,
        ca_name=None, ca_file=None, ca_common_name=None, keys_dir=None):

        HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.ca = CertificateAuthority(
          ca_name=ca_name, ca_file=ca_file, ca_common_name=ca_common_name, keys_dir=keys_dir)

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


class MitmProxyRequestHandler(ProxyRequestHandler):

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


