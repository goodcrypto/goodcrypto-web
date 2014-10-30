'''
    Web app forms.

    Copyright 2014 GoodCrypto
    Last modified: 2014-09-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from traceback import format_exc

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _

from goodcrypto import api_constants
from syr.log import get_log

log = get_log()



API_Actions = (
    (api_constants.STATUS, api_constants.STATUS), 
)

class APIForm(forms.Form):
    '''Handle a command through the API.'''
    
    action = forms.ChoiceField(required=False, 
       choices=API_Actions,
       error_messages={'required': _('You must select an action.')})

