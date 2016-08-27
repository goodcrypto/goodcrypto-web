'''
    Web views

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-04-25

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os.path, sh
from traceback import format_exc

from django.conf import settings
from django.shortcuts import render_to_response
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.template import RequestContext

from goodcrypto.web.api import WebAPI
from goodcrypto.web.constants import CA_FILE
from reinhardt.utils import is_secure_connection
from syr.log import get_log

log = get_log()

def home(request):
    '''Show the home page.'''

    form_template = 'web/home.html'
    is_secure = is_secure_connection(request)
    if request.method == 'POST':
        
        log('post: {}'.format(request.POST))
        try:
            if 'action' in request.POST:
                action = request.POST.__getitem__('action')
                log('action: {}'.format(action))
                if action == 'Get certificate':
                    response = download_certficate(request)
                elif action == 'View fingerprint':
                    response = HttpResponseRedirect('/web/show_fingerprint/')
                else:
                    response = render_to_response(
                        form_template, {'fingerprint': get_fingerprint(), 'secure': is_secure}, 
                        context_instance=RequestContext(request))
            else:
                log('POST: {}'.format(request.POST))
                response = render_to_response(form_template, {'secure': is_secure}, context_instance=RequestContext(request))
        except Exception:
            log(format_exc())
            response = render_to_response(form_template, context_instance=RequestContext(request))
    else:
        response = render_to_response(
            form_template, {'fingerprint': get_fingerprint(), 'secure': is_secure}, context_instance=RequestContext(request))

    return response

def configure(request):
    ''' Show how to configure mta. '''
    
    template = 'web/configure.html'
    return render_to_response(template, context_instance=RequestContext(request))

def import_certificate(request):
    ''' Show how to import the web certificate. '''
    
    template = 'web/certificate.html'
    return render_to_response(
      template, {'fingerprint': get_fingerprint()}, context_instance=RequestContext(request))

def show_fingerprint(request):
    '''Show the fingerprint of the web certificate.'''

    form_template = 'web/fingerprint.html'
    if request.method == 'POST':
        
        # we don't care what's in the form, just send the certificate
        response = download_certficate(request)
 
    else:
        log('showing web cert fingerprint')

        response = render_to_response(
            form_template, {'fingerprint': get_fingerprint()}, context_instance=RequestContext(request))

    return response


def download_certificate(request):
    '''Download the web' certificate.'''

    log('downloading web cert')
    
    if os.path.exists(CA_FILE):
        with open(CA_FILE) as f:
            filename = os.path.basename(CA_FILE)
            response = HttpResponse(f.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = 'attachment; filename="{}"'.format(filename)
            
    else:
        raise Http404('Web cert file not found.')

    return response


def get_fingerprint():
    '''Get the fingerprint of the web certificate.'''

    try:
        # get the fingerprint
        result = sh.openssl('x509', '-fingerprint', '-in', CA_FILE, '-md5')
        log('result: {}'.format(result.exit_code))
        if result.exit_code == 0:
            lines = result.stdout.split('\n')
            fingerprint = lines[0].replace('SHA1 Fingerprint=', '')
        else:
            fingerprint = result.stderr
    except Exception:
        log(format_exc())
        fingerprint = 'Unable to get fingerprint due to an unexpected error'


    return fingerprint

def api(request):
    '''Interface with the goodcrypto server through the API.
    
       All requests must be via a POST.
    '''

    try:
        referer = request.META.get('HTTP_REFERER', 'unknown')
        http_user_agent = request.META.get('HTTP_USER_AGENT', 'unknown')
        remote_ip = get_remote_ip(request)
        log.write('{} called web api from {} with {} user agent'.format(remote_ip, referer, http_user_agent))
        if remote_ip == '127.0.0.1':
            response = WebAPI().interface(request)
        else:
            # redirect attempts at using the api from outside the localhost
            response = HttpResponsePermanentRedirect('/')
    except:
        log.write(format_exc())
        response = HttpResponsePermanentRedirect('/')

    return response

