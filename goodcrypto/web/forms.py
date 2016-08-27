'''
    Web app forms.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-09-17

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from traceback import format_exc

from django import forms
from django.core.exceptions import ValidationError

from goodcrypto import api_constants
from goodcrypto.utils import i18n
from goodcrypto.web.models import Options
from syr.log import get_log

log = get_log()



API_Actions = (
    (api_constants.STATUS, api_constants.STATUS),
)

class APIForm(forms.Form):
    '''Handle a command through the API.'''

    action = forms.ChoiceField(required=False,
       choices=API_Actions,
       error_messages={'required':i18n('You must select an action.')})

class OptionsAdminForm(forms.ModelForm):

    class Meta:
        model = Options

        fields = [
                  'tor_middle_relay',
        ]

    class Media:
        js = ('/static/js/admin_js.js',)



