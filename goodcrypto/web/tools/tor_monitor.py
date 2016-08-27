#! /usr/bin/python
# -*- coding: utf-8 -*-

'''
    Monitor tor
    
    Periodically updates tor status file.
    Must be run in background as root.
    
    Copyright 2015 GoodCrypto
    Last modified: 2015-07-17
'''

# delete in python 3
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import re, sh, time
from traceback import format_exc

from goodcrypto.constants import STATUS_GREEN, STATUS_RED, STATUS_YELLOW, TOR_STATUS_FILE

import syr.user
from syr.log import get_log

user = syr.user.whoami()
if user != 'root':
    sys.exit('Must be run as root. User is {}'.format(user))
    
log = get_log()

def tor_check():
    
    LOG_FILE = '/var/log/tor/notices.log'
    START_PATTERN = r'opening.*log file.'
    BOOTSTRAPPED_PATTERN = r'Bootstrapped (\d+)%'
    INTERRUPT_PATTERN = r'Interrupt:'
    # add patterns that need a tor restart
    RESTART_NEEDED = (INTERRUPT_PATTERN, )
    
    percent = 0

    # decide if we need to restart tor
    NOT_RUNNING = 'not running'
    
    reason_for_restart = None
    
    # check status
    try:
        result = sh.service('tor', 'status')
    except:
        reason_for_restart = NOT_RUNNING
    else:
        if NOT_RUNNING in str(result):
            reason_for_restart = NOT_RUNNING
        
    # check log 
    if not reason_for_restart:
                    
        last_match = None
        
        try:
            with open(LOG_FILE) as tor_log:
                for line in tor_log:
                        
                    if re.search(START_PATTERN, line) or re.search(INTERRUPT_PATTERN, line):
                        percent = 0
                        last_match = line
                        
                    else:
                        match = re.search(BOOTSTRAPPED_PATTERN, line)
                        if match:
                            percent_string = match.group(1)
                            percent = int(percent_string)
                            last_match = line
                        
        except:
            pass
        
        if any(re.search(pattern, last_match) for pattern in RESTART_NEEDED):
            reason_for_restart = last_match
            
    # if reason then restart
    if reason_for_restart:
        
        log.debug('Restarting tor: {}'.format(reason_for_restart))
        
        percent = 0
        
        # tor appears to need time between stop and start, so we don't use restart
        try:
            sh.service('tor', 'stop')
        except:
            # it doesnt matter if it's already stopped
            pass
        time.sleep(5)
        sh.service('tor', 'start')
            
    return percent
        
while True:
    
    try:
        tor_percent = tor_check()
        
        if tor_percent <= 0:
            status = STATUS_RED
        elif tor_percent >= 100:
            status = STATUS_GREEN
        else:
            status = STATUS_YELLOW
            
        with open(TOR_STATUS_FILE, 'w') as status_file:
            status_file.write(status)
            
    except:
        # just log it and try again
        log.debug(format_exc())
                
    time.sleep(30)

