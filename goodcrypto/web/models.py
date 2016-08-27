'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-09-17
'''
from django.db import models

from goodcrypto.constants import WEB_DB
from goodcrypto.utils import i18n

class Options(models.Model):
    '''
        Options used by GoodCrypto Web.

        >>> options = Options.objects.all()
        >>> options is not None
        True
        >>> len(options) == 1
        True
    '''

    tor_middle_relay =  models.BooleanField(i18n('Tor middle relay'), default=True,
       help_text=i18n("Uncheck if you can't afford the bandwidth."))

    def __unicode__(self):
        return '{}'.format(self.tor_middle_relay)

    class Meta:
        verbose_name = i18n('options')
        verbose_name_plural = verbose_name

if __name__ == "__main__":
    import doctest
    doctest.testmod()

