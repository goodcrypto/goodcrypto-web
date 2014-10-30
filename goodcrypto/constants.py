'''
    Constants for GoodCrypto web.

    Copyright 2014 Good Crypto
    Last modified: 2014-10-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import os.path

# set this to False to ship
WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP = False
if WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP:
    WARNING = 'WARNING! WARNING! WARNING! TESTING ONLY! DO NOT SHIP!'
    
GOODCRYPTO_DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

