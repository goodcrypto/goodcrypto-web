#! /usr/bin/python3
# -*- coding: utf-8 -*-

'''
    Monitor tor

    Restarts tor as needed. Periodically updates tor status file
    with 'green', 'yellow', or 'red'.

    Must be run as root.

    Copyright 2015-2016 GoodCrypto
    Last modified: 2016-10-10
'''

import sys
IS_PY2 = sys.version_info[0] == 2

if IS_PY2:
    reload(sys)
    sys.setdefaultencoding('utf-8')

import re, sh, time, threading
from traceback import format_exc

try:
    from goodcrypto.constants import STATUS_GREEN, STATUS_RED, STATUS_YELLOW
    from goodcrypto.webfirewall.constants import TOR_STATUS_FILE
except:
    try:
        from webfirewall.goodcrypto.constants import STATUS_GREEN, STATUS_RED, STATUS_YELLOW
        from webfirewall.constants import TOR_STATUS_FILE
    except:
        # stand alone
        STATUS_GREEN = 'green'
        STATUS_RED = 'red'
        STATUS_YELLOW = 'yellow'
        TOR_STATUS_FILE = '/tmp/tor_status'

import syr.lock
import syr.user
import syr.times
from syr.log import get_log

NOT_RUNNING = 'not running'
CHECK_INTERVAL = 30 # seconds
START_DEADLINE_SECONDS = 5 * 60 # seconds

user = syr.user.whoami()
if user != 'root':
    sys.exit('Must be run as root. User is {}'.format(user))

log = get_log()

tor_connect_timer = None
last_status = None

def tor_check():
    ''' Decide if we need to restart tor. '''

    """
        When we reset tor, that leaves us vulnerable to an attacker 
        DoSing a good connection to force us to a compromised 
        connection. Doesn't tor just try to get a new connection anyway?
    """

    def matched_restart_pattern(line):
        RESTART_PATTERNS = (r'Interrupt:',
                            r'Giving up',
                            r'Retrying on a new circuit',
                            r'assuming established circuits no longer work')

        return any(re.search(pattern, line) for pattern in RESTART_PATTERNS)

    LOG_FILE = '/var/log/tor/notices.log'
    START_PATTERN = r'opening.*log file.'
    BOOTSTRAPPED_PATTERN = r'Bootstrapped (\d+)%'

    percent = 0
    last_line_matched = None

    # check status
    if tor_running():

        # check log
        try:
            with open(LOG_FILE) as tor_log:
                for line in tor_log:

                    line = line.strip()

                    if matched_restart_pattern(line):
                        # log.debug('matched RESTART_PATTERNS: {}'.format(line))
                        last_line_matched = line

                    # don't restart if tor is connecting and hasn't timed out
                    match = re.search(BOOTSTRAPPED_PATTERN, line)
                    if match:
                        percent = int(match.group(1))
                        # log.debug('matched BOOTSTRAPPED_PATTERN: {}'.format(line))
                        last_line_matched = line

        except Exception as exc:
            log.debug(exc)

    else:
        last_line_matched = NOT_RUNNING

    # if reason then restart
    if matched_restart_pattern(last_line_matched):
        percent = 0
        log.debug('Restart tor: {}'.format(last_line_matched))
        restart_tor()

    return percent

def tor_running():
    running = False
    try:
        result = sh.bash('-c', 'service tor status')
    except Exception as exc:
        log.debug(exc)
    else:
        if NOT_RUNNING in str(result):
            log.debug('service tor status: {}'.format(str(result)))
        else:
            running = True
    return running

def restart_tor():
    log.debug("tor appears to need time between stop and start, so we don't use restart")
    stop_tor()
    time.sleep(5)
    start_tor()

def start_tor():
    log.debug('start tor')
    try:
        sh.bash('-c', 'service tor start')
    except Exception as exc:
        print(exc)
        raise
    else:
        reset_timer()

def stop_tor():
    log.debug('stop tor')
    cancel_timer()
    try:
        sh.bash('-c', 'service tor stop')
    except Exception as exc:
        print(exc)
        # it doesnt matter if it's already stopped
        pass

def timed_out():
    log.debug('tor timed out')
    with syr.lock.locked():
        restart_tor()

def start_timer():
    global tor_connect_timer

    with syr.lock.locked():
        if timer_set():
            log.debug('timer already started')
        else:
            # threading.Timer seems too unreliable, or at least too quirky
            tor_connect_timer = syr.times.now() + (START_DEADLINE_SECONDS * syr.times.one_second)
            log.debug('set tor timer for {}'.format(tor_connect_timer))

def cancel_timer():
    global tor_connect_timer

    with syr.lock.locked():
        if timer_set():
            log.debug('cancel timer')
            tor_connect_timer = None

def reset_timer():
    cancel_timer()
    start_timer()

def timer_set():
    return tor_connect_timer is not None

def run():
    global last_status

    log.debug('start tor monitor')

    if not tor_running():
        start_tor()
    start_timer()

    while True:

        try:
            tor_percent = tor_check()

            if tor_percent <= 0:
                status = STATUS_RED
                start_timer()

            elif tor_percent >= 100:
                status = STATUS_GREEN
                cancel_timer()

            else:
                status = STATUS_YELLOW
                start_timer()

            if status != last_status:
                last_status = status
                log.debug('status: {}'.format(status))
            with open(TOR_STATUS_FILE, 'w') as status_file:
                status_file.write(status)

        except:
            # just log it and try again
            log.debug(format_exc())

        # timed out?
        if tor_connect_timer and syr.times.now() > tor_connect_timer:
            timed_out()

        time.sleep(CHECK_INTERVAL)

run()
