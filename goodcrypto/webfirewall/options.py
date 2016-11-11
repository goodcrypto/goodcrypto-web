'''
    Manage GoodCrypto Web's options.

    Copyright 2015-2016 GoodCrypto
    Last modified: 2016-08-01
'''
try:
    from goodcrypto.constants import WEB_DB
except:
    from webfirewall.goodcrypto.constants import WEB_DB
from reinhardt.singleton import get_singleton, save_singleton
from syr.exception import record_exception
from syr.log import get_log
from syr.lock import locked

log = get_log()


def is_tor_middle_relay_active():
    '''
       Determine whether tor middle relay is active or not.

       >>> enabled = is_tor_middle_relay_active()
       >>> set_tor_middle_relay_active(True)
       >>> is_tor_middle_relay_active()
       True
       >>> set_tor_middle_relay_active(enabled)
    '''

    return get_options().tor_middle_relay


def set_tor_middle_relay_active(enable):
    '''
       Set the user prefers to show images.

       >>> enabled = is_tor_middle_relay_active()
       >>> set_tor_middle_relay_active(True)
       >>> is_tor_middle_relay_active()
       True
       >>> set_tor_middle_relay_active(enabled)
    '''

    record = get_options()
    record.tor_middle_relay = enable
    save_options(record)

def get_options():
    '''
        Get the mail options.

        >>> get_options() is not None
        True
    '''

    try:
        from goodcrypto.webfirewall.models import Options
    except:
        from webfirewall.models import Options

    try:
        record = get_singleton(Options, db=WEB_DB)
    except Options.DoesNotExist:
        with locked():
            record = Options.objects.create(tor_middle_relay=True, db=WEB_DB)
            record.save()
    except:
        record_exception()

    return record


def save_options(record):
    '''
        Save the mail options.

        >>> save_options(get_options())
    '''
    try:
        from goodcrypto.webfirewall.models import Options
    except:
        from webfirewall.models import Options

    save_singleton(Options, record, db=WEB_DB)

