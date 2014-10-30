'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-09-29

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import json, os
from traceback import format_exc

from django.contrib.auth.models import User
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.http import HttpResponsePermanentRedirect

from goodcrypto import api_constants
from goodcrypto.web import get_web_status
from goodcrypto.web.forms import APIForm
from syr.log import get_log
from syr.utils import get_remote_ip

log = get_log()

class WebAPI(object):
    '''Handle the API for GoodCrypto Web.'''
    
    def interface(self, request):
        '''Interface with the server through the API.
        
           All requests must be via a POST.
        '''
    
        # final results and error_messages of the actions
        result = None
        
        ok = False
        response = None
    
        try:
            self.action = None
            self.ip = get_remote_ip(request)
            log.write('attempting web api call from {}'.format(self.ip))

            if request.method == 'POST':
                try:
                    form = APIForm(request.POST)
                    if form.is_valid():
                        cleaned_data = form.cleaned_data

                        self.action = cleaned_data.get(api_constants.ACTION_KEY)
                        log('action: {}'.format(self.action))

                        ok, result = self.take_api_action()
    
                    else:
                        result = self.format_bad_result('Invalid form')
                        self.log_attempted_access(result)
                
                        log('api form is not valid')
                        self.log_bad_form(request, form)
                    
                except:
                    result = self.format_bad_result('Unknown error')
                    self.log_attempted_access(result)

                    log(format_exc())
                    log('unexpected error while parsing input')
            else:
                self.log_attempted_access('Attempted GET connection')
                
                log('redirecting api GET request to website')
                response = HttpResponsePermanentRedirect(api_constants.SYSTEM_API_URL)
                        
            if response is None:
                response = self.get_api_response(request, result)
                
        except:
            log(format_exc())
            response = HttpResponsePermanentRedirect(api_constants.SYSTEM_API_URL)
    
        return response
    
    
    def take_api_action(self):
    
        result = None
        
        ok, error_message = self.is_data_ok()
        if ok:
            if self.action == api_constants.STATUS:
                result = self.format_result(api_constants.STATUS, get_web_status())
                log('web status result: {}'.format(result))
                
            else:
                ok = False
                error_message = 'Bad action: {}'.format(self.action)
                result = self.format_bad_result(error_message)
                log('bad action result: {}'.format(result))
    
        else:
            result = self.format_bad_result(error_message)
            log('data is bad')
    
        return ok, result
    
    def is_data_ok(self):
        '''Check if all the required data is present.'''
        
        error_message = ''
        ok = False
        
        if self.has_content(self.action):
            if self.action == api_constants.STATUS:
                ok = True
                log('status request found')
                
            else:
                ok = False
                error_message = 'Missing required data'
                log('missing required data')

        else:
            ok = False
            error_message = 'Missing required action'
            log('missing required action')
            
        return ok, error_message

    def has_content(self, value):
        '''Check that the value has content.'''
        
        try:
            str_value = str(value)
            if str_value is None or len(str_value.strip()) <= 0:
                ok = False
            else:
                ok = True
        except:
            ok = False
            log(format_exc())
            
        return ok
            
    def format_result(self, action, ok, error_message=None):
        '''Format the action's result.'''
    
        if error_message is None:
            result = {api_constants.ACTION_KEY: action, api_constants.OK_KEY: ok}
        else:
            result = {
              api_constants.ACTION_KEY: action, 
              api_constants.OK_KEY: ok, 
              api_constants.ERROR_KEY: error_message
            }
            
        return result
        
    def format_bad_result(self, error_message):
        '''Format the bad result for the action.'''
        
        result = None
        
        if self.action and len(self.action) > 0:
            result = self.format_result(self.action, False, error_message)
        else:
            result = self.format_result('Unknown', False, error_message)
            
        log('action result: {}'.format(error_message))
    
        return result
        
    
    def get_api_response(self, request, result):
        ''' Get API reponse as JSON. '''

        json_result = json.dumps(result)
        log('json results: {}'.format(''.join(json_result)))
    
        response = render_to_response('web/api_response.html',
            {'result': ''.join(json_result),}, 
            context_instance=RequestContext(request))
        
        return response
    
    
    def log_attempted_access(self, results):
        '''Log an attempted access to the api.'''
     
        log('attempted access from {} for {}'.format(self.ip, results))
        
    def log_bad_form(self, request, form):
        ''' Log the bad fields entered.'''
        
        # see django.contrib.formtools.utils.security_hash()
        # for example of form traversal
        for field in form:
            if (hasattr(form, 'cleaned_data') and 
                field.name in form.cleaned_data):
                name = field.name
            else:
                # mark invalid data
                name = '__invalid__' + field.name
            log('name: {}; data: {}'.format(name, field.data))
        try:
            if form.name.errors:
                log('  ' + form.name.errors)
            if form.email.errors:
                log('  ' + form.email.errors)
        except:
            pass
    
        log('logged bad api form')


