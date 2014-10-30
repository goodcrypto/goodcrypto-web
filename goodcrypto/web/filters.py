#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
    Web filters.
    
    Requirements
      
      * tor
      * pymiproxy
      * goodcrypto web
      
    Certificate authority file is written to ca_file, specified below.
    Import the cert file into your browser. Firefox example:
       * Edit / Preferences / Advanced / Encryption / View Certificates / Authorities / Import
       * Select the ca_file
    You may have to delete an earlier version of the cert from your browser first.
   
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-19

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

# drop privileges immediately
# !! this only appears to work on the dev system
#    on the dist system the python sh module suddenly decides its globals 
#    are all set to None.
# ideally this program should have been launched as an unprivileged user 
from goodcrypto.web.constants import USER, HTTP_PROXY_PORT, TOR_PORT
from syr.user import drop_privileges
try:
    drop_privileges(USER)
    dropped_privileges = True
except:
    dropped_privileges = False

from goodcrypto.constants import HTTP_PROXY_URL, WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP

# torify must be called before any imports that may do net io
from syr.net import torify
torify(port=TOR_PORT)

from datetime import datetime
import email.utils

from syr.times import now, timedelta_to_seconds

# delete in python 3
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import httplib, os, re, sh, time, traceback, urlparse
from HTMLParser import HTMLParser
import miproxy.proxy

import syr, syr.http, syr.utils
from syr.html import firewall_html
from syr.log import get_log
from syr.fs import makedir, DEFAULT_PERMISSIONS_DIR_OCTAL
from syr.process import program_from_port

from goodcrypto.web.constants import (
    SECURITY_DATA_DIR, CA_NAME, CA_FILE, USER, USER_GROUP, HTTP_PROXY_PORT)

#miproxy.proxy.connect_timeout = 60 # seconds

log = get_log('web.filters.log', recreate=True)

if not os.path.isdir(SECURITY_DATA_DIR):
    # both goodcrypto and www-data need read access to the web cert
    makedir(SECURITY_DATA_DIR, owner=USER, group='www-data')

encoding = 'utf8'

mitm_proxy = None

class WebFilter(miproxy.proxy.RequestInterceptorPlugin, miproxy.proxy.ResponseInterceptorPlugin):

    def __init__(self, *args, **kwargs):
        
        logname = 'web.filter.{}.log'.format(self.__class__.__name__)
        self.log = get_log(logname, recreate=True)
        
        super(WebFilter, self).__init__(*args, **kwargs)

    def do_request(self, request):
                
        try:
                
            prefix, params = self.filter_request(request)
            params = self.filter_request_params(params)
            
            filtered_request = (
                prefix + syr.http.http_eol + 
                syr.http.params_to_str(params) + syr.http.http_separator)
            if filtered_request != request:
                self.log.debug('filtered request summary: {}'.format(self.summary(filtered_request))) #DEBUG
                self.log.debug('request summary: {}, filtered request summary: {}'.format(len(request), len(filtered_request))) #DEBUG
                request = filtered_request
                
        except:
            # just log it
            self.report_exception()
            
        return request

    def do_response(self, response):
        
        try:
            prefix, params, data = self.filter_response(response)
            params = self.filter_response_params(params)
            
            # filter html
            if syr.http.is_html(params):
            
                filtered_html = self.filter_html(data)
                if filtered_html != data: 
                    data = filtered_html
                    #DEBUG self.log.debug('filtered html: {}'.format(data))

            # re-encode from unicode if needed
            charset = syr.http.content_encoding_charset(params)
            if charset is not None:
                data = data.encode(charset, 'ignore')
            
            filtered_response = (
                prefix + syr.http.http_eol + 
                syr.http.params_to_str(params) + syr.http.http_separator + 
                data)
            if filtered_response != response:
                #self.log.debug('filtered response summary: {}'.format(self.summary(filtered_response))) #DEBUG
                #self.log.debug('response summary: {}, filtered response summary: {}'.format(len(response), len(filtered_response))) #DEBUG
                response = filtered_response
                
        except:
            self.log.debug('    response replaced by error response {}'.format(self.summary(response)))
            response = self.report_exception()
            
        return response

    def filter_request(self, request):
        ''' Override this function to filter request. 
        
            Default is no filtering. 
        
            Returns (prefix, params) so we don't parse the request twice.
        '''

        prefix, params = syr.http.parse_request(request)
        return prefix, params
        
    def filter_response(self, response):
        ''' Override this function to filter response. 
        
            Default is no filtering. 
        
            Returns (prefix, params, data) so we don't parse the response twice.
        '''
            
        # parsing also decompresses and decodes to unicode
        prefix, params, data = syr.http.parse_response(response)
        return prefix, params, data
        
    def filter_html(self, html):
        ''' Override this function to filter html. 
        
            Default is no filtering. 
        '''
        
        return html

    def filter_request_params(self, params):
        ''' Override this function to filter request params. 
        
            Default is no filtering. 
        '''
        
        return params
    
    def filter_response_params(self, params):
        ''' Override this function to filter response params. 
        
            Default is no filtering. 
        '''
        
        return params
    
    def summary(self, data, bytes=1000):
        # indent
        line_separator = '\r\n   '
        summary_data = data.strip()[:bytes]
        if summary_data != data:
            summary_data += '...'
        return line_separator + summary_data.replace(syr.http.http_eol, line_separator)
    
    def report_exception(self):
        msg = 'filter: {}, \n{}'.format(self.__class__.__name__, traceback.format_exc())
        log.debug(msg)
        self.log.debug(msg)
        
        html = '''
            <head>
                <title>GoodCrypto Web error</title>
            </head>
            <body>
                <h2>GoodCrypto Web error</h2>
                Technical details:
                
                <pre>{}</pre>
            </body>
        '''.format(msg).strip()
        response = syr.http.create_response(httplib.INTERNAL_SERVER_ERROR, data=html)
        
        return response
    
    def remove_param(self, params, name, why):
        ''' Remove a header from params. 
        
            'why' may include {} which is replaced by the param value. 
        '''
    
        if name in params:
            value = params[name]
            del params[name]
            msg = '"{}: {}" deleted {}'.format(name, value, why)
            self.log.debug(msg)
                
        return params
    
class HtmlFirewallFilter(WebFilter):
    ''' Firewall html.
    
            Clearly, the untrusted user's input should not be allowed 
            to cause the application to run arbitrary programs.
            
            David A. Wheeler
            Secure Programming for Linux and Unix
    
        Default deny, then whitelist html.
        
        Only allow plain html. For example, no executables.
        Css allows embedding of executables, and we don't have a css parser.
        So the 'style' tag and attribute are not allowed.
    '''
    
    def filter_html(self, html):
        ''' Whitelist plain html.
        
            Whitelist good tags. Reject all others. For some tags start 
            skipping html until tag is closed.
            
            Blacklist bad attributes within tags.
        '''
                
        return firewall_html(html)

class TimeFilter(WebFilter):
    ''' Track time as reported by http servers. 
    
        When the time is significantly off, it may indicate packet staining. 
    '''
    
    SECONDS_MARGIN = 30
    
    def filter_response_params(self, params):
        ''' Filter response params to track time. 
        
            If a host time is badly off from local time,
            log a warning.
            
            What we really need is to track consensus time from multple 
            servers and alert user if local time is off too much.
        '''

        http_date = params.get('Date')
        
        if http_date:
            
            try:
                host_time = datetime.fromtimestamp(
                    email.utils.mktime_tz(
                        email.utils.parsedate_tz(http_date)))
                # self.log.debug('Datetime: {}'.format(host_time))
                seconds_off = timedelta_to_seconds(host_time - now())
                
            except Exception as exc:
                self.log.debug('bad http_date: {}\n{}'.format(http_date, traceback.format_exc()))
                
            else:
                if abs(seconds_off) > self.SECONDS_MARGIN:
                    self.log.warning(
                        'host time off {} seconds from local time'.
                        format(seconds_off))
                
        else:
            self.log.debug('missing date')
                
        return params
      
class BreachVulnFilter(WebFilter):
    ''' Disable http compression to avoid BREACH vuln. 
    
        See [http://en.wikipedia.org/wiki/BREACH_%28security_exploit%29 BREACH (security exploit) - Wikipedia, the free encyclopedia]
    '''
    
    def filter_request_params(self, params):
        ''' Filter request params. 
        
            Disable http compression. 
        '''

        return self.remove_param(params, 
            'Accept-Encoding', 'to avoid BREACH vuln')

class NoRefererFilter(WebFilter):
    ''' Remove referer from requests to avoid browser tracking. '''
    
    def filter_request_params(self, params):
        ''' Remove referer. '''

        return self.remove_param(params,
            'Referer','to avoid link click tracking')
        
class CookieFilter(WebFilter):
    ''' Remove cookies from requests to avoid browser tracking. 
    
        See NSA uses Google cookies to pinpoint targets for hacking
            http://www.washingtonpost.com/blogs/the-switch/wp/2013/12/10/nsa-uses-google-cookies-to-pinpoint-targets-for-hacking/
            NSA surveillance and third-party trackers: How cookies help government spies.
            http://www.slate.com/blogs/future_tense/2013/12/13/nsa_surveillance_and_third_party_trackers_how_cookies_help_government_spies.html
            
        Allowing host-only cookies doesn't help, because spies tap the main pipes and see all cookies.
        Allowing ssl-only cookies doesn't help, because spies also get data directly from sites like Google.
        
        Deleting all cookies works.
        But it makes sites that track you very unhappy.
        Specifically the site may not remember that you're logged in.
        
        We'll probably want to make this filter very configurable.
    '''
    
    def filter_request_params(self, params):
        ''' Remove cookie. '''

        return self.remove_param(params, 
            'Cookie', 'to avoid browser tracking')
        
    def filter_response_params(self, params):
        ''' Remove cookie. '''

        return self.remove_param(params, 
            'Set-Cookie', 'to avoid browser tracking')
        
class SpoofUserAgentFilter(WebFilter):
    ''' Replace user-agent to avoid browser tracking. 

        Hide in the crowd.
        
        Ideally report a user-agent that misleads malware.
        If an attacker sends us a hidden payload, we'd rather it was for a different system.
    '''
    
    def filter_request_params(self, params):
        ''' Replace user-agent. '''

        # use common user-agent strings to hide in the crowd
        # eff panopticon pages seem to be inaccessible. stunning, i know.
        # 2013-06 chrome seems to be most common, then firefox
        #     https://en.wikipedia.org/wiki/Usage_share_of_web_browsers
        # agent strings
        #     http://useragentstring.com/pages/Chrome/
        #     http://useragentstring.com/pages/Firefox/
        #     http://www.useragentstring.com/Android%20Webkit%20Browser_id_18070.php
        chrome_common_agent = 'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36'
        firefox_common_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0'
        common_agent = chrome_common_agent
        apple_android_agent = 'Mozilla/5.0 (Linux; U; Android 2.2; en-sa; HTC_DesireHD_A9191 Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1'
        
        if 'User-agent' in params:
            old_value = params['User-agent']
        else:
            old_value = ''
            
        if 'Apple' in old_value:
            new_value = common_agent
        else:
            new_value = apple_android_agent
        params['User-agent'] = new_value
        self.log.debug('"User-agent" replaced to avoid browser tracking. old: {}, new: {}'.
            format(old_value, new_value))
        
        return params

class LogFilter(WebFilter):
    ''' Log proxy activity. 
        
        !! This should be a user option.
        
        Dangerous info to log. All of this onfo was already in the logs. 
        Now it's in one place.
    '''
    
    def filter_request(self, request):
        ''' Log request. 
        
            Returns (prefix, params) so we don't parse the request twice.
        '''

        prefix, params = syr.http.parse_request(request)
        if syr.http.is_app_data(params):
            # header only
            header = syr.http.header(request)
            self.log.debug('parsed request header summary: {}'.format(self.summary(header)))
                
        else:
            self.log.debug('parsed request summary: {}'.format(self.summary(request)))
            
        return prefix, params

    def filter_response(self, response):
        ''' Log response. 
        
            Returns (prefix, params, data) so we don't parse the response twice.
        '''
            
        # parsing also decompresses and decodes to unicode
        prefix, params, data = syr.http.parse_response(response)
        
        self.log.debug('parsed response:')
        self.log.debug('    {}'.format(prefix))
        for name in params:
            self.log.debug('    {} = {}'.format(name, params[name]))
        self.log.debug('    data length: {}'.format(len(data)))
        #DEBUG if syr.http.is_text(params):
        #DEBUG     self.log.debug('    {}'.format(data)) # format(self.summary(data)))
            
        return prefix, params, data
          
class LogUrlFilter(WebFilter):
    ''' Log url. 
        
        !! This should be a user option.
        
        Dangerous info to log. This info was already in the logs but in pieces.
    '''
    
    def filter_request(self, request):
        ''' Log request. 
        
            Returns (prefix, params) so we don't parse the request twice.
        '''

        prefix, params = syr.http.parse_request(request)
        if 'Host' in params:
            parts = prefix.split()
            if len(parts) == 3:
                command, local_url, protocol = tuple(parts)
                command = command.upper()
                if command == 'GET' or command == 'POST' or command == 'HEAD':
                    protocol = protocol.upper()
                    if protocol.startswith('HTTPS'):
                        protocol = 'https'
                    else:
                        protocol = 'http'
                    url = protocol + '://' + params['Host'] + local_url
                    self.log.debug(url)
            
        return prefix, params

def proxy(ca_name=None, ca_file=None):
    ''' Configure mitm proxy. '''
    
    global mitm_proxy
    
    try:
        mitm_proxy = miproxy.proxy.AsyncMitmProxy(
            ca_name=ca_name, 
            ca_file=ca_file, 
            server_address=('', HTTP_PROXY_PORT))
    except Exception as exc:
        log.debug(syr.utils.last_exception())
        if "Address already in use" in str(exc):
            # program = program_from_port(HTTP_PROXY_PORT)
            # log.debug('port {} already in use by "{}"'.format(HTTP_PROXY_PORT, program))
            msg = 'port {} already in use. Is VBoxHeadless running?'.format(HTTP_PROXY_PORT)
            print(msg)
            log.debug(msg)
            sys.exit(msg)
        raise
    
    if WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP:
        mitm_proxy.register_interceptor(LogFilter)
        mitm_proxy.register_interceptor(LogUrlFilter)
    mitm_proxy.register_interceptor(HtmlFirewallFilter)
    mitm_proxy.register_interceptor(BreachVulnFilter)
    mitm_proxy.register_interceptor(NoRefererFilter)
    mitm_proxy.register_interceptor(CookieFilter)
    mitm_proxy.register_interceptor(SpoofUserAgentFilter)
    mitm_proxy.register_interceptor(TimeFilter)
    
    try:
        mitm_proxy.serve_forever()
    # except KeyboardInterrupt:
    finally:
        # don't hide earlier errors
        try:
            mitm_proxy.server_close()
        except:
            pass
    
def main():
    if not dropped_privileges:
        log.debug('could not drop privileges t user {}'.format(USER))
    log.debug('HTTP proxy at {}'.format(HTTP_PROXY_URL))
    proxy(ca_name=CA_NAME, ca_file=CA_FILE)

if __name__ == '__main__':
    ''' run doctests as "python -m doctest -v proxy.py" '''
    main()

