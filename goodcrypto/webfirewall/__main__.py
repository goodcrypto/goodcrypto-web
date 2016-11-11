#! /usr/bin/python3
# -*- coding: utf-8 -*-

'''
    Firewall a web browser.

    Chains proxies to do a thorough job.
    Restarts proxies as needed.

    To add a proxy:
       1. If there is not a Proxy subclass for the proxy type, add one.
          * Implement Proxy.start().
          * If "kill -HUP' is not the right way to stop the proxy,
            implement Proxy.stop().
       2. In main() add a proxy instance and call proxy.watch().

    This module is largely a process monitor. It monitors process health,
    not just that a process is alive.

    Because this module uses watchdog threads, and threads do not inherit
    globals, globals are passed around. Imports appear where they're
    needed. That makes this program overly complex.
    It might be better to use a standard watchdog program.
    A standard monitor would also solve dropping privileges, but most
    wouldn't monitor process health, specifically active ports.
    We want to detect when a process locks up, not just when it dies.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-09-05

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.

    >>> from syr.process import program_from_port
    >>> try:
    ...     from goodcrypto.webfirewall.constants import HTTP_PROXY_PORT
    ...     from goodcrypto.vms import start_host_system_services, stop_host_system_services
    ... except:
    ...     from webfirewall.constants import HTTP_PROXY_PORT
    ...     from webfirewall.goodcrypto.vms import start_host_system_services, stop_host_system_services
    
    >>> stop_host_system_services()

    >>> program = program_from_port(HTTP_PROXY_PORT)
    >>> assert program is None, ('{} already listening on http proxy port {}'.
    ...     format(program, HTTP_PROXY_PORT)))

    >>> start_host_system_services()

'''
from __future__ import unicode_literals

import sys
IS_PY2 = sys.version_info[0] == 2

if IS_PY2:
    reload(sys)
    sys.setdefaultencoding('utf-8')

import os, sh, signal, socket, stat, threading
from subprocess import check_output
import traceback

if IS_PY2:
    from httplib import HTTPConnection
else:
    from http.client import HTTPConnection

"""
    Unfortunately we don't drop privileges here immediately, as we should.
    We try to drop them when we launch filters.py and in filters.py.
    But it's not working well. In this module the error is:

        DEBUG sudo: unable to stat /etc/sudoers: Permission denied

    The /etc/sudoers ownership/permissions look identical to working systems.

    In filters.py syr.user.su() works on the dev system.
    But on the dist system the python sh module suddenly decides its globals
    are all set to None.

    Maybe we don't have to run as root at all.

    We have to know if tor is running. Our standard way, when we know
    the port, is to parse output from "fuser --namespace tcp 9050".
    But fuser requires root.

    Possible solutions:
      * Run tor as a different user. Tor-browser does it. A good choice for the user is 'goodcrypto'.
      * Use another way to find out if someone is listening on a port
        * We actually started by polling the port, which is very noisy (logs, wireshark)
        * The noise might well be worth it if we can't find a better solution

# drop privileges immediately
try:
    from goodcrypto.webfirewall.constants import USER
except:
    from webfirewall.constants import USER
from syr.user import su
su(USER)
"""

import shutil

from syr.log import get_log
from syr.dict import DictObject
from syr.user import sudo
import syr.utils
from syr.fs import edit_file_in_place
from syr.utils import stacktrace
from syr.times import now, one_second, timedelta_to_seconds
from syr.redir import redir_stdout, redir_stderr

try:
    from goodcrypto.webfirewall.constants import USER, USER_GROUP, HTTP_PROXY_PORT, TOR_PORT
except:
    from webfirewall.constants import USER, USER_GROUP, HTTP_PROXY_PORT, TOR_PORT

# usewithtor is not needed if downstream proxies know how to use tor
# python apps should call syr.net.torify()
use_usewithtor = False

log = get_log('webfirewall.main.log', recreate=True)

localhost = '127.0.0.1' # use ip as string, not 'localhost'

proxies = []

class Proxy(object):
    ''' Proxy server manager '''

    INITIAL_PERIOD = 10 # seconds
    RETRY_PERIOD = 60 # seconds

    def __init__(self, name, program, host, port):
        ''' Initialize. '''

        self.name = name
        self.program = program
        self.host = host
        self.port = port

        self.watchdog_timer = None
        self.restarting = False

        logname = self.name.replace(' ', '.')
        self.logfile = '{}.output.log'.format(logname)
        self.log = get_log(self.logfile, recreate=True)

        # make this namespace available in threads
        namespace = {}
        namespace.update(globals())
        namespace.update(locals())
        self.namespace = DictObject(namespace)

    def start(self):
        ''' Start proxy.

            Example::

                def start(self):
                    """ Start proxy """

                    sh.service.myproxy.start()
        '''

        self.namespace.log.debug('start {}'.format(self))
        raise Exception('Not implemented') # replace with a standard exception

    def stop(self):
        ''' Stop proxy '''

        self.namespace.log.debug('stop {}'.format(self))
        try:
            self.namespace.log.debug('kill -HUP {}'.format(pid))
            sh.kill('-HUP', self.pid)
        except:
            pass

    def restart(self):
        ''' Restart proxy '''

        self.namespace.log.debug('restart {}'.format(self))
        try:
            self.stop()
            self.start()
        except:
            self.namespace.log.debug(traceback.format_exc())
            raise

    def check_process(self):
        ''' Check the proxy and restart as needed. '''

        # self.namespace.log.debug('check {}'.format(self))
        if self.is_up():
            if self.restarting:
                self.namespace.log.info('up: {}'.format(self))
                self.restarting = False

        else:
            self.namespace.log.info('down: {}'.format(self))
            self.namespace.log.info('    possibly more info in {}'.
                format(self.logfile))
            # use restart() so we always do an explicit stop()
            self.restarting = True
            self.restart()

        self.set_watchdog(self.RETRY_PERIOD)

    def set_watchdog(self, interval):
        ''' Set watchdog timer. '''

        # self.namespace.log.info('set watchdog timer {}'.format(self))
        self.watchdog_timer = self.namespace.threading.Timer(
            interval, self.namespace.Proxy.check_process, args=(self,))
        self.watchdog_timer.start()

    def watch(self):
        ''' Start watching proxy '''

        if not self.watchdog_timer:
            # some proxies are already starting or up, so wait before checking
            self.set_watchdog(self.INITIAL_PERIOD)

    def is_up(self):
        ''' Test if the proxy is running. '''

        import sh
        from syr.process import pid_from_port, program_from_pid

        up = False

        try:
            program_running = False
            port_listening = False

            for line in sh.ps('ax', columns=1000, _iter=True):
                if self.program in line:
                    program_running = True

            if program_running:

                # if anyone is listening on self.port
                self.pid = pid_from_port(self.port)
                if self.pid:
                    self.listening_program = program_from_pid(self.pid)
                    port_listening = True

                else:
                   self.namespace.log.debug(
                       'program not listening: {}'.
                       format(self))

            else:
                self.namespace.log.debug('program not running: {}'.format(self.program))

            up = program_running and port_listening

            #if not up: #DEBUG
            #    self.namespace.log.debug(stacktrace()) #DEBUG

        except:
            self.namespace.log.debug(traceback.format_exc())
            up = False

        return up

    def process_output(self, output):
        output = output.rstrip()
        print(output) #DEBUG
        self.log.debug()

    def __str__(self):
        return '{} on {}:{}'.format(self.name, self.host, self.port)

    if IS_PY2:
        def __unicode__(self):
            return '%s' % str(self)

class HttpProxy(Proxy):
    ''' HTTP proxy server manager '''

    def is_up(self):
        ''' Test connection through an http proxy. '''

        ''' is there a good webfirewall test domain?
            if we use goodcrypto.com people will say we're phoning home
            example.com is intended for docs, not live testing
            microsoft uses contoso.com for its own testing
            eff, theguardian, cnn etc. all are real domains
            we especially don't want to drain the coffers of someone like eff '''
        test_domain = 'cnn.com'

        # self.namespace.log.debug('HttpProxy.is_up() {}'.format(self)) #DEBUG
        up = super(HttpProxy, self).is_up()
        # self.namespace.log.debug('HttpProxy.is_up() {} super up {}'.format(self, up)) #DEBUG
        if up:

            try:
                # weirdly, HTTPConnection() gets the proxy and set_tunnel() gets the destination domain
                # self.namespace.log.debug('HttpProxy.is_up() {} connecting'.format(self)) #DEBUG
                conn = HTTPConnection(self.host, self.port)
                # self.namespace.log.debug('HttpProxy.is_up() {} connected'.format(self)) #DEBUG
                conn.set_tunnel(test_domain)

                conn.request('GET', '/')
                # self.namespace.log.debug('HttpProxy.is_up() {} getting response'.format(self)) #DEBUG
                r1 = conn.getresponse()
                # self.namespace.log.debug('HttpProxy.is_up() {} got response {}'.format(self, r1.status)) #DEBUG
                assert r1.status == 200
                assert r1.reason == 'OK'
                data1 = r1.read()
                assert len(data1)
                conn.close()

                up = True

            except:
                self.namespace.log.debug(traceback.format_exc())
                up = False

        return up

class TorProxy(Proxy):

    def __init__(self, host, port):
        ''' Initialize. '''

        super(TorProxy, self).__init__('tor', '/usr/bin/tor', host, port)

    def start(self):
        ''' Start proxy '''

        import sh

        self.namespace.log.debug('start {}'.format(self))
        if not self.is_up():
            self.namespace.log.warning('tor was not already up')
            try:
                sh.service.tor.restart(_out=self.process_output, _err=self.process_output)
            except:
                self.namespace.log.debug(traceback.format_exc())

    def stop(self):
        ''' Stop proxy '''

        import sh
        self.namespace.log.debug('stop {}'.format(self))
        sh.service.tor.stop()

class WebProxy(Proxy):

    def __init__(self, host, port):
        ''' Initialize. '''

        super(WebProxy, self).__init__(
            'webfirewall filters',
            os.path.join(os.path.dirname(__file__), 'filters.py'),
            host, port)

    def start(self):
        ''' Start proxy '''

        self.namespace.log.debug('start {}'.format(self))

        # if True:
        with sudo(USER):

            if use_usewithtor:
                self.namespace.log.debug('start with usewithtor {}'.format(self)) #DEBUG
                self.web_process = sh.usewithtor.python(
                    self.program,
                    _out=self.process_output, _err=self.process_output, _bg=True)
                self.namespace.log.debug('started with usewithtor {}'.format(self)) #DEBUG

            else:
                import sh
                self.namespace.log.debug('start without usewithtor {}'.format(self)) #DEBUG
                self.web_process = sh.python3(
                    self.program,
                    _out=self.process_output, _err=self.process_output, _bg=True)
                self.namespace.log.debug('started without usewithtor {}'.format(self)) #DEBUG

    def process_wait(self):
        self.web_process.wait()

def status(msg):
    ''' Print and log status.

        >>> status('test status')
        'test status'
        >>> import sh
        >>> assert 'test status' in sh.tail(log.filename)

    '''

    global log

    print(msg)
    log.info(msg)

def catch_exit_signals():
    """ Catch system exit signals.

        If we leave threads running when we call sys.exit(), we can get a race.
        The error message is:

            Exception in thread ... (most likely raised during interpreter shutdown)

        Since this error only occurs intermittently, we don't know if this code works
        unless it fails.
    """

    def handle_exit_signal(signal_num, frame):
        """ Handle a system exit signal. """

        global log
        global proxies

        msg = 'handle exit signal {}'.format(signal_num)
        print(msg)
        log.error(msg)
        if frame:
            log.debug(frame)

        for proxy in proxies:
            # cancel() only works if the Timer hasn't timed out
            proxy.watchdog_timer.cancel()
        # let any watchdogs that have timed out have time to finish
        os.sleep(10)

        sys.exit(msg)

    signals_that_kill = [
        signal.SIGHUP,
        signal.SIGINT,
        signal.SIGQUIT,
        signal.SIGILL,
        signal.SIGABRT,
        signal.SIGFPE,
        # signal.SIGKILL,
        signal.SIGSEGV,
        signal.SIGTERM,
        # signal.SIGSTOP,
        signal.SIGTSTP,
        ]

    for signal_num in signals_that_kill:
        # log.debug('signal_num {}'.format(signal_num)) # DEBUG
        signal.signal(signal_num, handle_exit_signal)

def profile():
    ''' Profile goodcrypto webfirewall. '''

    PROFILE = '/tmp/goodcrypto.webfirewall.prof'
    INTERVAL = 1800 # seconds

    try:
        EXEC = 'goodcrypto.webfirewall.__main__.main()'
        syr.utils.profile_command(EXEC, PROFILE, INTERVAL)
    except:
        EXEC = 'webfirewall.__main__.main()'
        syr.utils.profile_command(EXEC, PROFILE, INTERVAL)

def main():
    ''' Run goodcrypto webfirewall

        >>> main()
        starting...
        started
    '''

    try:
        status('starting...')

        # this call causes __main__.py to exit silently after starting WebProxy
        # catch_exit_signals()

        # for now we rely on Tails to restart tor as needed
        # what about on dev systems or when we don't use Tails?
        # tor = TorProxy(localhost, TOR_PORT)
        # tor.watch()
        # proxies.append(tor)

        web = WebProxy(localhost, HTTP_PROXY_PORT)
        web.watch()
        proxies.append(web)

        status('started')

    except:
        log.debug(traceback.format_exc())

if __name__ == '__main__':
    main()
    # profile()

