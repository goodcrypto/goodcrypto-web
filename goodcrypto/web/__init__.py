'''
    GoodCrypto web app

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-10-13

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

from goodcrypto.constants import STATUS_GREEN, STATUS_RED, STATUS_YELLOW, TOR_STATUS_FILE
from syr.log import get_log
from syr.process import is_program_running

log = get_log()

def get_web_status():
    '''
        Return whether Web app is running.

        >>> status = get_web_status()
        >>> status.lower().find('red') >= 0
        True
    '''

    program_running = is_program_running('web/filters.py')
    try:
        with open(TOR_STATUS_FILE, 'r') as status_file:
            tor_status = status_file.read()
            if tor_status:
                tor_status = tor_status.strip()
            else:
                tor_status = STATUS_RED
    except:
        tor_status = STATUS_RED

    if program_running:
        status = tor_status
    else:
        status = STATUS_RED

    log('web status: {}'.format(status))

    return status


