#! /usr/bin/python
# -*- coding: utf-8 -*-

'''
    Web filters.

    Requirements

      * tor
      * pymiproxy
      * goodcrypto web

    To use openssl version of proxy, search for openssl in this file to see necessary changes.

    Certificate authority file is written to ca_file, specified below.
    Import the cert file into your browser. Firefox example:
       * Edit / Preferences / Advanced / Encryption / View Certificates / Authorities
       * If you have an old version of the cert:
         * Select the old cert
         * "Delete or distrust"
       * "Import"
       * Select the ca_file

    Copyright 2016 GoodCrypto
    Last modified: 2016-03-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

# drop privs before we have a syr log
import os, sys, traceback

try:

    print('start {}'.format(__file__)) # DEBUG

    # drop privileges immediately
    # ideally this program should have been launched as an unprivileged user
    import syr.user
    from goodcrypto.web.constants import USER

    syr.user.force(USER)

except Exception as exc:
    # no syr log yet
    drop_privs_log_name = '/tmp/web.filter.drop.privs.log'
    print('could not drop privileges')
    with open(drop_privs_log_name, 'a') as drop_privs_log:
        drop_privs_log.write('could not drop privileges\n')
        drop_privs_log.write('{}\n'.format(exc))
        drop_privs_log.write(traceback.format_exc() + '\n')
        drop_privs_log.write('exiting\n')
    print('details in {}'.format(drop_privs_log_name))
    os._exit(-1)

try:

    # delete in python 3
    import sys
    reload(sys)
    sys.setdefaultencoding('utf-8')

    from goodcrypto.constants import (
        HTTP_PROXY_URL, WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP)

    # torify must be called before any imports that may do net io
    from goodcrypto.web.constants import TOR_PORT
    from syr.net import torify
    torify(port=TOR_PORT)

    from datetime import datetime
    import email.utils

    from syr.times import now, timedelta_to_seconds

    import httplib, os, re, sh, time, traceback, urlparse
    from HTMLParser import HTMLParser
    import miproxy.proxy

    import syr, syr.http, syr.utils
    from syr.html import firewall_html
    from syr.log import get_log
    from syr.fs import makedir, DEFAULT_PERMISSIONS_DIR_OCTAL
    from syr.process import program_from_port

    from goodcrypto.web.constants import (
        SECURITY_DATA_DIR, CA_NAME, CA_FILE, CA_COMMON_NAME, KEYS_DATA_DIR, USER, USER_GROUP, HTTP_PROXY_PORT)

    log = get_log()

    if not os.path.isdir(SECURITY_DATA_DIR):
        # both goodcrypto and www-data need read access to the web cert
        makedir(SECURITY_DATA_DIR, owner=USER, group='www-data')

    encoding = 'utf8'

    #miproxy.proxy.connect_timeout = 60 # seconds
    mitm_proxy = None

except Exception as exc:
    print(traceback.format_exc())
    from syr.log import get_log
    log = get_log()
    log.error(exc)
    log.error(traceback.format_exc())
    raise

class WebFilter(
    miproxy.proxy.RequestInterceptorPlugin,
    miproxy.proxy.ResponseInterceptorPlugin):

    def __init__(self, *args, **kwargs):

        logname = 'web.filter.{}.log'.format(self.__class__.__name__)
        self.exception = None
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
                self.log.debug('filtered request summary: {}'.
                    format(self.summary(filtered_request))) #DEBUG
                self.log.debug('request summary: {}, filtered request summary: {}'.
                    format(len(request), len(filtered_request))) #DEBUG
                request = filtered_request

        except Exception as exc:
            msg = self.log_exception()
            self.abort_request(msg)

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
                #self.log.debug('filtered response summary: {}'.
                #    format(self.summary(filtered_response))) #DEBUG
                #self.log.debug('response summary: {}, filtered response summary: {}'.
                #    format(len(response), len(filtered_response))) #DEBUG
                response = filtered_response

        except:
            self.log.debug('    response replaced by error response {}'.
                format(self.summary(response)))
            html = self.exception_html()
            response = syr.http.create_response(httplib.INTERNAL_SERVER_ERROR, data=html)

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
        try:
            prefix, params, data = syr.http.parse_response(response)
        except IOError as ioe:
            log.debug(traceback.format_exc())
            raise

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

    def log_exception(self):
        msg = 'filter: {}, \n{}'.format(self.__class__.__name__, traceback.format_exc())
        log.debug(msg)
        self.log.debug(msg)
        return msg

    def exception_html(self):
        msg = self.log_exception()

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
        
        return html

    def remove_param(self, params, name, why):
        ''' Remove a header from params. '''

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
        
        Filter unsafe content types from request.

        Only allow plain html. No BLOBs. For example, no executables.
        Css allows embedding of executables, and we don't have a css parser.
        So the 'style' tag and attribute are not allowed.
    '''

    def unused_filter_request(self, request):
        ''' NOT WORKING. Filter unsafe content types from request.

            Returns (prefix, params) so we don't parse the request twice.
        '''

        UNSAFE_CONTENT_TYPES = ['application', 'image']

        prefix, params = syr.http.parse_request(request)
            
        self.log('HtmlFirewallFilter params:') # DEBUG
        for param in params: # DEBUG
            self.log('    {}: {}'.format(param, params[param])) # DEBUG
            
        PARAM_NAME = 'accept'

        if PARAM_NAME in params:
            types = params[PARAM_NAME]
            self.log('original {}: {}'.format(PARAM_NAME, types))
            filtered_types = []
            
            for content_type in types.split(','):
                content_type = content_type.strip().lower()
                
                for unsafe_type in UNSAFE_CONTENT_TYPES:
                    if content_type.startswith(unsafe_type):
                        self.log('removed content-type: {}'.
                                 format(content_type))
                    else:
                        filtered_types.append(content_type)
                        
            if filtered_types:
                params[PARAM_NAME] = ','.join(filtered_types)
            else:
                del params[PARAM_NAME]
            
        return prefix, params
        
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
                self.log.debug('bad http_date: {}\n{}'.
                    format(http_date, traceback.format_exc()))

            else:
                if abs(seconds_off) > self.SECONDS_MARGIN:
                    self.log.warning(
                        'host time off {} seconds from local time'.
                        format(seconds_off))

        else:
            self.log.debug('missing date')

        return params

class TrackingBeaconFilter(WebFilter):
    ''' Remove commom tracking beacon headers.

        Obviously what we really need is to default deny headers, and
        whitelist only what's safe.

        See
          * Simple test page for Cellular ISP tracking beacons - by Kenn White
            http://lessonslearned.org/sniff
          * Verizon Injecting Perma-Cookies to Track Mobile Customers, Bypassing Privacy Controls | Electronic Frontier Foundation
            https://www.eff.org/deeplinks/2014/11/verizon-x-uidh
          * http://www.reddit.com/r/technology/comments/2kt1j6/somebodys_already_using_verizons_id_to_track/
          * https://web.archive.org/web/20141027194059/https://github.com/Funnerator/fast_tim_conf/blob/master/lua/id_set.lua
          * search: propublica.views.acrButton

        Propublica's code from
        http://www.reddit.com/r/technology/comments/2kt1j6/somebodys_already_using_verizons_id_to_track/::

            <script>
            propublica.views.acrButton = propublica.View.extend({
              id : "run-demo",
              tag : "a",

              bindings : {
                click : "runDemo"
              },

              getAcrData : function(data) {
                var ids = {
                      "HTTP_X_UIDH"     : "Verizon",
                      "HTTP_X_ACR"      : "AT&T",
                      "HTTP_X_VF_ACR"   : "Vodafone",
                      "HTTP_X_UP_SUBNO" : "AT&T",
                      "HTTP_X_UP_VODACOMGW_SUBID" : "",
                      "HTTP_X_PIPER_ID" : "",
                      "HTTP_X_MSISDN"   : ""
                    };

                for (userHeader in data) {
                  if (ids[userHeader]) {
                    return {
                      "carrier" : ids[userHeader],
                      "id"      : data[userHeader]
                    }
                  }
                }
                return false;
              },

              runDemo : function(e) {
                e.preventDefault();
                var that = this;
                $.getJSON( "http://projects.propublica.org/jd/acr.json", function( data ) {
                    $(".hideafterclick").hide();
                    var tracker = that.getAcrData(data);
                    if (tracker) {
                      $("#uid").text(tracker.id)
                      $("#carrier").html(tracker.carrier)
                      $(".result").show();
                    } else {
                      $(".noresult").show();
                    }
                });
              }
            });
            </script>


                <div class="pp-interactive" id="tracking-button">
                    <h2 class="pp-int-hed">
                        Does Your Phone Company Track You?</h2>
                    <div id="tracking-demo">
                        <div class="hideafterclick">
                            <a class="action" id="run-demo" href="#">Check for Tracking Code</a><p>Click from your smartphone or tablet (with Wi-Fi turned off) to see if your telecom provider is adding a tracking number. We don't save any information.</p>
                                        <p class="pp-interactive-source">Al Shaw and Jonathan Stray, ProPublica</p>
                        </div>
                        <p class="result">Your <span id="carrier"></span> personal tracking code is</p>
                        <p class="result code" id="uid">token</p>
                        <p class="result">This is being sent by your carrier to every site you visit using this device.</p>
                        <p class="noresult">You are not being tracked by your carrier, or not viewing this on a mobile network.</p>
                    </div>
                </div>
    '''

    def filter_request_params(self, params):
        ''' Filter request params to remove tracking headers. '''

        return self.filter_params(params)

    def filter_response_params(self, params):
        ''' Filter response params to remove tracking headers. '''

        return self.filter_params(params)

    def filter_params(self, params):
        BAD_HEADERS = {
            'UIDH': 'Verizon Unique Identifier Header',
            'ACR': 'AT&T',
            'VF_ACR': 'Vodafone',
            'UP_SUBNO': 'AT&T',
            'UP_VODACOMGW_SUBID': '',
            'PIPER_ID': '',
            'MSISDN': ''
            }
        # !! do we really need to look for all these prefixes?
        # diffferent press reports and sample code show them differently
        PREFIXES = ['HTTP_X_', 'X_', 'X-']

        for suffix in BAD_HEADERS:
            source = BAD_HEADERS[suffix]
            for prefix in PREFIXES:
                params = self.remove_param(params,
                    prefix + suffix, 'Tracking header from {}'.format(source))

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
        If an attacker sends us a hidden payload, we'd rather it was for
        a different system.
    '''

    def filter_request_params(self, params):
        ''' Replace user-agent. '''

        # use common user-agent strings to hide in the crowd

        # 2013-06 chrome seems to be most common, then firefox
        #     https://en.wikipedia.org/wiki/Usage_share_of_web_browsers
        # agent strings
        #     http://useragentstring.com/pages/Chrome/
        #     http://useragentstring.com/pages/Firefox/
        #     http://www.useragentstring.com/Android%20Webkit%20Browser_id_18070.php
        chrome_common_agent = 'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36'
        firefox_common_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0'
        common_agent = chrome_common_agent
        # Panopticlick (https://panopticlick.eff.org/index.php?action=log)
        # reports apple_android_agent as one in 1568125.67 browsers
        # this is very bad
        apple_android_agent = 'Mozilla/5.0 (Linux; U; Android 2.2; en-sa; HTC_DesireHD_A9191 Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1'
        apple_ipad_agent = 'Mozilla/5.0 (iPad; U; CPU OS 3_2_1 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Mobile/7B405'
        # many more at http://www.useragentstring.com/pages/Browserlist/

        if 'User-agent' in params:
            old_value = params['User-agent']
        else:
            old_value = ''

        if 'Apple' in old_value:
            new_value = firefox_common_agent
        else:
            new_value = chrome_common_agent
        params['User-agent'] = new_value
        self.log.debug('"User-agent" replaced to avoid browser tracking. old: {}, new: {}'.
            format(old_value, new_value))

        return params

class LogFilter(WebFilter):
    ''' Log proxy activity.

        !! This should be a user option.

        Dangerous info to log. All of this info was already in various logs.
        But now it's in one place.
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

def proxy(ca_name=None, ca_file=None, ca_common_name=None, keys_dir=None):
    ''' Configure mitm proxy. '''

    global mitm_proxy

    try:
        log.debug('init proxy')
        mitm_proxy = miproxy.proxy.AsyncMitmProxy(
            ca_name=ca_name,
            ca_file=ca_file,
            ca_common_name=ca_common_name,
            keys_dir=keys_dir,
            server_address=('', HTTP_PROXY_PORT))
    except Exception as exc:
        log.debug(traceback.format_exc())
        if "Address already in use" in str(exc):
            msg = 'port {} already in use'.format(HTTP_PROXY_PORT)
            try:
                msg += 'by {}'.format(program_from_port(HTTP_PROXY_PORT))
            except:
                log.debug('Ignoring error for now: \n{}'.format(traceback.format_exc()))
            # msg = 'port {} already in use. Is VBoxHeadless running?'.format(HTTP_PROXY_PORT)
            print(msg)
            log.debug(msg)
            sys.exit(msg)
        raise

    log.debug('start registering filters')
    if WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP:
        mitm_proxy.register_interceptor(LogFilter)
        mitm_proxy.register_interceptor(LogUrlFilter)
    mitm_proxy.register_interceptor(HtmlFirewallFilter)
    mitm_proxy.register_interceptor(TrackingBeaconFilter)
    mitm_proxy.register_interceptor(BreachVulnFilter)
    mitm_proxy.register_interceptor(NoRefererFilter)
    mitm_proxy.register_interceptor(CookieFilter)
    mitm_proxy.register_interceptor(SpoofUserAgentFilter)
    mitm_proxy.register_interceptor(TimeFilter)

    log.debug('start proxy')
    try:
        mitm_proxy.serve_forever()
    except Exception as exc:
        log.error(exc)
        sys.exit(exc)
    else:
        log.debug('started proxy')
    finally:
        # don't hide earlier errors
        try:
            log.debug('close proxy server')
            mitm_proxy.server_close()
        except:
            pass

def main():
    try:
        log.debug('start main')
        log.debug('HTTP proxy at {}'.format(HTTP_PROXY_URL))
        proxy(ca_name=CA_NAME, ca_file=CA_FILE, ca_common_name=CA_COMMON_NAME, keys_dir=KEYS_DATA_DIR)
    except Exception as exc:
        log.error(traceback.format_exc())
    else:
        log.debug('started main')

if __name__ == '__main__':
    ''' run doctests as "python -m doctest -v proxy.py" '''
    main()

print('end {}'.format(__file__)) # DEBUG
