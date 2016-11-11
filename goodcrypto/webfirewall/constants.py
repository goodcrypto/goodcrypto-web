'''
    GoodCrypto Web constants

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-08-06

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from __future__ import unicode_literals

import os.path, sh, tempfile

try:
    from goodcrypto.constants import (GOODCRYPTO_DATA_DIR,
                                      WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP)
    WEB_DATA_DIR = os.path.join(GOODCRYPTO_DATA_DIR, 'webfirewall')
except:
    from webfirewall.goodcrypto.constants import WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP
    WEB_DATA_DIR = os.path.join('~', 'webfirewall-data')

SECURITY_DATA_DIR = os.path.join(WEB_DATA_DIR, 'security')
KEYS_DATA_DIR = os.path.join(WEB_DATA_DIR, 'keys')

# domain or ip of the system running the hypervisor
VM_HOST = '127.0.0.1'
HTTP_PROXY_PORT = 8398
HTTP_PROXY_URL = 'http://{}:{}'.format(VM_HOST, HTTP_PROXY_PORT)

TOR_PORT = 9350

# tor status file
TMP_DIR = '/tmp'
TOR_STATUS_FILENAME = 'goodcrypto.tor.status'
if os.path.exists(TMP_DIR):
    TOR_STATUS_FILE = os.path.join('/tmp', TOR_STATUS_FILENAME)
else:
    TOR_STATUS_FILE = os.path.join(tempfile.mkdtemp(), TOR_STATUS_FILENAME)

try:
    HOSTNAME = sh.uname(nodename=True).strip()
except OSError as os_error:
    import time, syr.log

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

