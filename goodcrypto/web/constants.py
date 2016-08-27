'''
    GoodCrypto Web constants

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-10-10

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import os.path, sh

from goodcrypto.constants import *

WEB_DATA_DIR = os.path.join(GOODCRYPTO_DATA_DIR, 'web')
SECURITY_DATA_DIR = os.path.join(WEB_DATA_DIR, 'security')
KEYS_DATA_DIR = os.path.join(WEB_DATA_DIR, 'keys')

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

CA_NAME = 'GoodCrypto Private Server Certificate Authority'
CA_COMMON_NAME = 'goodcrypto.private.server.proxy'
CA_FILE = os.path.join(SECURITY_DATA_DIR, 'web.ca.crt')

USER = 'goodcrypto'
USER_GROUP = USER

