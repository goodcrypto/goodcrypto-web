'''
    Manage GoodCrypto Web's options.

    Copyright 2015 GoodCrypto
    Last modified: 2015-11-21
'''
from goodcrypto.utils.exception import record_exception
from reinhardt.singleton import get_singleton, save_singleton
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

    from goodcrypto.web.models import Options

    try:
        record = get_singleton(Options)
    except Options.DoesNotExist:
        with locked():
            record = Options.objects.create(tor_middle_relay=True)
            record.save()

    return record


def save_options(record):
    '''
        Save the mail options.

        >>> save_options(get_options())
    '''
    from goodcrypto.web.models import Options

    save_singleton(Options, record)

