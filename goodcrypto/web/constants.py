'''
    GoodCrypto Web constants
    
    Copyright 2014 GoodCrypto
    Last modified: 2014-09-22

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import os.path, sh

from goodcrypto.constants import *

WEB_DATA_DIR = os.path.join(GOODCRYPTO_DATA_DIR, 'web')
SECURITY_DATA_DIR = os.path.join(WEB_DATA_DIR, 'security')

""" Why are we getting an "out of pty devices" error here?
    It seems to have started when we changed chr to try to umount /proc more.
    Previously chr did not umount /proc at all, in case there was a 
    background task running. Now chr checks its command line for a trailing &, 
    and if none does the umount.
    
    This program has background tasks that don't involve a command line &.
    But the app vm's rc.local seems to invoke the web chroot's rc.local 
    in the background, with a trailing &. And the web chroot's rc.local 
    starts the web filtering proxy with a trailing &. 
    
    After waiting a few minutes, rerunning the code gets no error.
"""
try:
    HOSTNAME = sh.uname(nodename=True).strip()
except OSError as os_error:
    import time, syr.logs
    
    log = syr.log.get_log()
    log.error(str(os_error))
    if 'out of pty devices' in str(os_error):
        for file in ['/proc/sys/kernel/pty/max', '/proc/sys/kernel/pty/nr']:
            log.error('{}: {}'.format(file, sh.cat(file).strip()))
    
    # a wait seems to help
    time.sleep(30) # how long?
    HOSTNAME = sh.uname(nodename=True).strip()
    
CA_NAME = 'GoodCrypto Server - ' + HOSTNAME
CA_FILE = os.path.join(SECURITY_DATA_DIR, 'web.ca.crt')

USER = 'goodcrypto'
USER_GROUP = USER

