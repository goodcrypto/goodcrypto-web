'''
    GoodCrypto web app
    
    Copyright 2014 GoodCrypto
    Last modified: 2014-09-29

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

from goodcrypto.utils import is_program_running
from syr.log import get_log

log = get_log()

def get_web_status():
    '''
        Return whether Web app is running.

        >>> status = get_web_status()
        >>> status.lower().find('active') >= 0
        True
    '''

    running = is_program_running('web/filters.py')

    log('web is running: {}'.format(running))

    return running
    

