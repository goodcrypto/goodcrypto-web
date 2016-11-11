'''
    Webfirewall forms.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-08-01

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from traceback import format_exc

from django import forms
from django.core.exceptions import ValidationError

try:
    from goodcrypto.webfirewall.models import Options
except:
    from webfirewall.models import Options
    
from syr.log import get_log

log = get_log()



class OptionsAdminForm(forms.ModelForm):

    class Meta:
        model = Options

        fields = [
                  'tor_middle_relay',
        ]

    class Media:
        js = ('/static/js/admin_js.js',)



