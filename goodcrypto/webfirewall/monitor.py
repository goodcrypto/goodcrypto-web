'''
    GoodCrypto webfirewall

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-09-22

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
try:
    from goodcrypto.constants import STATUS_GREEN, STATUS_RED, STATUS_YELLOW
    from goodcrypto.webfirewall.constants import TOR_STATUS_FILE
except:
    from webfirewall.constants import TOR_STATUS_FILE
    from webfirewall.goodcrypto.constants import STATUS_GREEN, STATUS_RED, STATUS_YELLOW
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

    program_running = is_web_running()
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

def is_web_running():
    '''
        Return whether Web app is running.

        >>> is_web_running()
        True
    '''

    return is_program_running('webfirewall/__main__.py') or is_program_running('webfirewall/filters.py')


