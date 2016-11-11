'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-08-01
'''
from django.db import models
from django.utils.encoding import python_2_unicode_compatible

try:
    from goodcrypto.constants import WEB_DB
except:
    from webfirewall.goodcrypto.constants import WEB_DB
    
@python_2_unicode_compatible
class Options(models.Model):
    '''
        Options used by GoodCrypto Webfirewall.

        >>> options = Options.objects.all()
        >>> options is not None
        True
        >>> len(options) == 1
        True
        >>> if len(options) != 1:
        ...    len(options)
    '''

    tor_middle_relay =  models.BooleanField('Tor middle relay', default=True,
       help_text="Uncheck if you can't afford the bandwidth.")

    def __str__(self):
        return '{}'.format(self.tor_middle_relay)

    class Meta:
        verbose_name = 'options'
        verbose_name_plural = verbose_name

if __name__ == "__main__":
    import doctest
    doctest.testmod()

