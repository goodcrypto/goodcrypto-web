#! /usr/bin/python3
# -*- coding: utf-8 -*-

'''
    Webfirewall filters. Filter http connect, request, response header, response, and html.

    Requirements

      * tor
      * pymiproxy
      * goodcrypto webfirewall

    Certificate authority file is written to ca_file, specified below.
    Import the cert file into your browser. Firefox example:
       * Edit / Preferences / Advanced / Encryption / View Certificates / Authorities
       * If you have an old version of the cert:
         * Select the old cert
         * "Delete or distrust"
       * "Import"
       * Select the ca_file

    To do
      * Add html filter to add rel="noopener" to target="_blank"
        The target="_blank" vulnerability by example
        https://dev.to/ben/the-targetblank-vulnerability-by-example

    Ideally this filter will help bypass censorship. See AllowSave filter. Some future test urls:
      * http://www.nbclosangeles.com/news/weird/Cardboard-Bank-Robber-Holds-Off-SWAT-for-Hours.html
      * http://ipv4.google.com/sorry/IndexRedirect?continue=http://www.google.com/search%3Fstrip%3D1%26q%3Dcache:http%253A%252F%252Fwww.nbclosangeles.com%252Fnews%252Fweird%253F1%252FCardboard-Bank-Robber-Holds-Off-SWAT-for-Hours.html%3Fstrip%3D1%26q%3Dcache:http%253A%252F%252Fwww.nbclosangeles.com%252Fnews%252Fweird%253F1%252FCardboard-Bank-Robber-Holds-Off-SWAT-for-Hours.html&q=CGMSBE33taUYzYOjvAUiGQDxp4NL3OwJhfNcFbRcNt_rK3teX3Rfr5s
        * "403. That’s an error. . . Your client does not have permission to get URL . . . from this server. That’s all we know."
        * 403 means Forbidden. Authorization won't help.

    Copyright 2016 GoodCrypto
    Last modified: 2016-09-05

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from __future__ import unicode_literals

import sys
IS_PY2 = sys.version_info[0] == 2

# drop privs before we have a syr log
import os, sys, traceback

# Warning: setting PROFILE to True sends stderr and stdout to the bitbucket
PROFILE = False

try:

    # drop privileges immediately
    # ideally this program should have been launched as an unprivileged user
    import syr.user
    from constants import USER

    syr.user.force(USER)

except Exception as exc:
    # no syr log yet
    drop_privs_log_name = '/tmp/webfirewall.filter.drop.privs.log'
    print('could not drop privileges')
    with open(drop_privs_log_name, 'a') as drop_privs_log:
        drop_privs_log.write('could not drop privileges\n')
        drop_privs_log.write('{}\n'.format(exc))
        drop_privs_log.write(traceback.format_exc() + '\n')
        drop_privs_log.write('exiting\n')
    print('details in {}'.format(drop_privs_log_name))
    os._exit(-1)

try:

    if IS_PY2:
        reload(sys)
        sys.setdefaultencoding('utf-8')

    from constants import (
        HTTP_PROXY_URL, TOR_PORT, WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP)

    # torify must be called before any imports that may do net io
    from syr.net import torify
    torify(port=TOR_PORT)

    from datetime import datetime
    import email.utils

    import os, re, sh, time, traceback
    if IS_PY2:
        from httplib import INTERNAL_SERVER_ERROR
        from HTMLParser import HTMLParser
        from urllib import quote_plus
        from urlparse import parse_qs, urlsplit
    else:
        from http.client import INTERNAL_SERVER_ERROR
        from html.parser import HTMLParser
        from urllib.parse import parse_qs, quote_plus, urlsplit

    import miproxy.proxy

    import syr, syr.http_utils, syr.utils
    from syr.html_utils import firewall_html
    from syr.http_utils import code as httpcode
    from syr.log import get_log
    from syr.fs import makedir, DEFAULT_PERMISSIONS_DIR_OCTAL
    from syr.process import program_from_port
    from syr.times import now, timedelta_to_seconds

    from constants import (
        SECURITY_DATA_DIR, CA_NAME, CA_FILE, CA_COMMON_NAME, KEYS_DATA_DIR,
        USER, USER_GROUP, HTTP_PROXY_PORT)

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

log.debug('python version: {}'.format(sys.version_info[0]))

class WebFilter(miproxy.proxy.InterceptorPlugin):

    def __init__(self, *args, **kwargs):

        logname = 'webfirewall.filter.{}.log'.format(self.__class__.__name__)
        self.exception = None
        self.log = get_log(logname, recreate=True)

        super(WebFilter, self).__init__(*args, **kwargs)

    def do_connect(self):
        self.filter_connect()

    def do_request(self, request):

        try:

            prefix, params, data = syr.http_utils.parse_request(request)
            prefix, params, data = self.filter_request(request, prefix, params, data)
            params = self.filter_request_params(params)

            filtered_request = (
                prefix + syr.http_utils.HTTP_EOL +
                syr.http_utils.params_to_str(params) + syr.http_utils.HTTP_SEPARATOR)
            if data:
                filtered_request = filtered_request + data

            if filtered_request != request:
                #DEBUG self.log.debug('filtered request summary: {}'.
                #DEBUG     format(self.summary(filtered_request))) #DEBUG
                #DEBUG self.log.debug('request summary: {}, filtered request summary: {}'.
                #DEBUG     format(len(request), len(filtered_request))) #DEBUG
                request = filtered_request

        except miproxy.proxy.StopRequest:
            raise
        except Exception as exc:
            msg = self.log_exception()
            raise

        return request

    def do_response(self, response):

        try:
            prefix, params, data = self.filter_response(response)

            if not data:
                self.log.warning('response has no data')

            # filter html
            if syr.http_utils.is_html(params):

                if data.strip() == '':
                    self.log.warning('unfiltered html is blank'.format(data))
                filtered_html = self.filter_html(data)
                if filtered_html != data:
                    self.log.debug('html was filtered')
                    # self.log.debug('unfiltered html: {}'.format(data))
                    # self.log.debug('filtered html: {}'.format(filtered_html))
                    data = filtered_html

                    if data.strip() == '':
                        self.log.warning('filtered html is blank'.format(data))

            # re-encode from unicode if needed
            charset = syr.http_utils.content_encoding_charset(params)
            if charset is not None:
                data = data.encode(charset, 'ignore')

            params['Content-Length'] = len(data)

            filtered_response = syr.http_utils.unparse_response(prefix, params, data)
            if filtered_response != response:
                #self.log.debug('filtered response summary: {}'.
                #    format(self.summary(filtered_response))) #DEBUG
                #self.log.debug('response summary: {}, filtered response summary: {}'.
                #    format(len(response), len(filtered_response))) #DEBUG
                response = filtered_response

        except miproxy.proxy.StopRequest:
            raise
        except:
            self.log.debug('    response replaced by error response {}'.
                format(self.summary(response)))
            html = self.exception_html()
            response = syr.http_utils.create_response(INTERNAL_SERVER_ERROR, data=html)

        return response

    def filter_connect(self):
        ''' Override this function to filter request.

            Default is no filtering.

            Call self.request_handler.stop_request() to refuse request.
        '''

    def filter_request(self, request, prefix, params, data):
        ''' Override this function to filter request.

            Default is no filtering.

            Call self.request_handler.stop_request() to refuse request.
        '''

        return prefix, params, data

    def filter_response(self, response):
        ''' Override this function to filter response.

            Default is no filtering.

            Returns (prefix, params, data) so we don't parse the response twice.
        '''

        # parsing also decompresses and decodes to unicode
        try:
            prefix, params, data = syr.http_utils.parse_response(response)
        except miproxy.proxy.StopRequest:
            raise
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
        summary_data = str(data).strip()[:bytes]
        if summary_data != str(data):
            summary_data += '...'
        return line_separator + summary_data.replace(syr.http_utils.HTTP_EOL, line_separator)

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

        name_to_remove = None
        for param in params:
            if name.lower() == param.lower():
                name_to_remove = param
        if name_to_remove:
            value = params[name_to_remove]
            del params[name_to_remove]
            assert name_to_remove not in params
            msg = '"{}: {}" deleted {}'.format(name, value, why)
            self.log.debug(msg)

        return params

class HtmlFilter(WebFilter):
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

    def filter_html(self, html):
        ''' Whitelist plain html.

            Whitelist good tags. Reject all others. For some tags start
            skipping html until tag is closed.

            Blacklist bad attributes within tags.
        '''

        filtered_html = firewall_html(html)
        if html != filtered_html:
            self.log('html was filtered')
            # self.log('unfiltered html:\n{}'.format(html))
            # self.log('filtered html:\n{}'.format(filtered_html))
        return filtered_html

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

        !! This should be a user option.
        Many sites send compressed data, e.g. gzip, even when we remove
        Accept-Encoding from the client request. Many people won't want
        to disable these sites. Updated mainstrean browsers aren't
        succeptible to BREACH. In some cases the unallowed compression
        disappears when the page is loaded, which may indicate a MITM attack.
    '''

    def filter_request_params(self, params):
        ''' Filter request params.

            Disable http compression.
        '''

        return self.remove_param(params,
            'Accept-Encoding', 'to avoid BREACH vuln')

    def filter_response_params(self, params):
        ''' Block compressed pages.

            Some sites compress pages even when there is no Accept-Encoding in the request.
        '''

        if 'Content-Encoding' in params:
            self.log.debug('"Content-Encoding: {}" in response header even though not allowed'.
                format(params['Content-Encoding']))
            self.request_handler.stop_request('For security compression is not accepted, but site used {}. Reloading may help'.
                                              format(params['Content-Encoding']),
                                              code=httpcode['Not Acceptable'])

        return params

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

class DomainFilter(WebFilter):
    ''' Block unwanted domains. Malware, tracking, etc.

        !! Sites should be a user option.
    '''

    # !! extend from public lists, e.g.:
    #    http://easylist-msie.adblockplus.org/malwaredomains_full.tpl
    #    malwaredomainlist.com
    #        http://www.malwaredomainlist.com/mdl.php
    #        Downloadable Lists - http://www.malwaredomainlist.com/forums/index.php?topic=3270.0
    #        follow the rules to download their lists:
    #            http://www.malwaredomains.com/wordpress/?p=2448
    #            "Violators are being banned daily."
    # regular expressions
    MALWARE_LIST = []
    TRACKER_LIST = [r'mozilla.net', # tracking-protection.cdn.mozilla.net, etc
                    r'services.mozilla.com',
                    r'self-repair.mozilla.org',
                    r'blocklist.addons.mozilla.org',
                    r'safebrowsing.cache.*google.com',
                    r'clients.*google.com',
                    r'cursoseventos.nic.br', # accessed often for no known reason. DNS?
                   ]
    WHITELIST = [r'addons.cdn.mozilla.net',]

    BLOCK_LIST = MALWARE_LIST + TRACKER_LIST
    BLOCKED_SITES = []
    for pattern in BLOCK_LIST:
        pattern = pattern + '$'
        BLOCKED_SITES.append(re.compile(pattern))
        subdomain_pattern = '.*\.' + pattern
        BLOCKED_SITES.append(re.compile(subdomain_pattern))
    WHITELISTED_SITES = []
    for pattern in WHITELIST:
        pattern = pattern + '$'
        WHITELISTED_SITES.append(re.compile(pattern))
        subdomain_pattern = '.*\.' + pattern
        WHITELISTED_SITES.append(re.compile(subdomain_pattern))

    def filter_connect(self):
        ''' Block unwanted domains. '''

        if self.blacklisted(self.request_handler.hostname):
            if self.whitelisted(self.request_handler.hostname):
                self.log.debug('whitelisted domain: {}'.format(self.request_handler.hostname))
            else:
                self.request_handler.stop_request('Blocked blacklisted site',
                                                  code=httpcode['Forbidden'])

    def whitelisted(self, domain):
        explicitly_good = False
        for gooddomain in DomainFilter.WHITELISTED_SITES:
            if gooddomain.match(domain):
                explicitly_good = True
        return explicitly_good


    def blacklisted(self, domain):
        bad = False
        for baddomain in DomainFilter.BLOCKED_SITES:
            if baddomain.match(domain):
                bad = True
        return bad

class LogFilter(WebFilter):
    ''' Log proxy activity.

        !! This should be a user option.

        Dangerous info to log. All of this info was already in various logs.
        But now it's in one place.
    '''

    def filter_request(self, request, prefix, params, data):
        ''' Log request.
        '''

        if syr.http_utils.is_app_data(params):
            # header only
            header = syr.http_utils.header(request)
            self.log.debug('parsed request header summary: {}'.format(self.summary(header)))

        else:
            self.log.debug('parsed request summary: {}'.format(self.summary(request)))

        return prefix, params, data

    def filter_response(self, response):
        ''' Log response.
        '''

        # parsing also decompresses and decodes to unicode
        prefix, params, data = syr.http_utils.parse_response(response)

        self.log.debug('parsed response:')
        self.log.debug('    {}'.format(prefix))
        for name in params:
            self.log.debug('    {} = {}'.format(name, params[name]))
        self.log.debug('    data length: {}'.format(len(data)))
        #DEBUG if syr.http_utils.is_text(params):
        #DEBUG     self.log.debug('    {}'.format(data)) # format(self.summary(data)))

        return prefix, params, data

class LogUrlFilter(WebFilter):
    ''' Log url.

        !! This should be a user option.

        Dangerous info to log. This info was already in the logs but in pieces.
    '''

    def filter_request(self, request, prefix, params, data):
        ''' Log request.

            Returns (prefix, params, data) so we don't parse the request twice.
        '''

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

        return prefix, params, data

class DuckDuckGoNoJSFilter(WebFilter):
    ''' Redirect DuckDuckGo to their NoJS page. This proxy blocks Javascript, so the standard url isn't enough.

        !! Sites should be a user option.
    '''

    def filter_request(self, request, prefix, params, data):
        ''' Redir to non-JS page.

            From:
                https://duckduckgo.com/html/?q=wget
            To:
                https://duckduckgo.com/html/?q=wget%20redirect%3Fq%3Dwget%20redirect
        '''

        if self.request_handler.hostname == 'duckduckgo.com':
            command, url, version = syr.http_utils.parse_prefix(prefix)
            parsed_url = urlsplit(url)
            # make sure not already non-JS url
            if parsed_url.path != '/html/':
                parsed_qs = parse_qs(parsed_url.query)
                if 'q' in parsed_qs:
                    q = quote_plus(parsed_qs['q'][0])
                    # is the "TERM redirect" supposed to be doubled?
                    url = '/html/?q={}%20redirect%3Fq%3D{}%20redirect'.format(q, q)
                    prefix = ' '.join([command, url, version])

        return prefix, params, data

class BlobFilter(WebFilter):
    ''' Block BLOBs (Binary Large OBjects).

        Malware hides in BLOBs. So no executables, images, etc. in requests.

        HtmlFilter separately blocks html img tags.

        !! Should be a user option.
    '''

    # todo: block on data types in request and response headers

    # !! extend this list
    IMAGE_FILE_EXTENSIONS = ('ico', 'icon', 'gif', 'png', 'tiff', 'tif', 'jpg', 'jpeg') # , 'pdf')

    def filter_request(self, request, prefix, params, data):
        ''' Block probable images in requests. '''

        # block on file extension. this is much less reliable
        command, url, version = syr.http_utils.parse_prefix(prefix)
        parsed_url = urlsplit(url)
        ext = parsed_url.path.lower().strip('/').split('.')[-1]
        if ext in BlobFilter.IMAGE_FILE_EXTENSIONS:
            self.request_handler.stop_request('Images are a major carrier of malware. Blocked probable image url .{}'.format(ext),
                                              code=httpcode['Unsupported Media Type'])

        return prefix, params, data

    def filter_request_params(self, params):
        ''' Filter unsafe content types from request. '''

        def is_unsafe_type(content_type):
            # !! it may be better to whitelist, i.e. only accept text/html
            unsafe = False
            for unsafe_type in UNSAFE_CONTENT_TYPES:
                if content_type.startswith(unsafe_type):
                    unsafe = True
            return unsafe

        UNSAFE_CONTENT_TYPES = ['*', 'application', 'image']

        PARAM_NAME = 'accept'

        if PARAM_NAME in params:
            unfiltered_types = params[PARAM_NAME]

            filtered_types = []

            for content_type in unfiltered_types.split(','):
                content_type = content_type.strip().lower()

                if is_unsafe_type(content_type):
                    self.log('removed content-type: {}'.format(content_type))
                else:
                    filtered_types.append(content_type)

            if filtered_types:
                value = ','.join(filtered_types)
                params[PARAM_NAME] = value
                self.log('filtered {} param: {}'.format(PARAM_NAME, params[PARAM_NAME]))
            else:
                del params[PARAM_NAME]

        return params

class AllowSaveFilter(WebFilter):
    ''' NOT WORKING. Allow pages to be saved.

        Sometimes the browser allows you to see a page, but not save it.
        The seems to invariably show no message about the save either
        on screen, or in logs after they are enabled.

        Some cases caused by "file name too long". Reddit is particularly prone to this.

        Some cases caused by bug. Data length changed but Content-Length didn't. Added:
            params['Content-Length'] = len(data)
        Other cases seen with none of our software running, using Google Chrome.

        This filter was prompted by the discovery that Firefox successfully
        received some pages and silently refused to save them. They appear to
        consistently be pages unfavorable to the government. This may be
        a targeted attack.

        We carefully verified that Firefox gets the page to save from
        our proxy. But it silently doesn't save it. This behavior is
        a known Firefox bug when the user doesn't have write permission
        to the dir. In our test cases, the user had full rights to the
        dir.

        When Firefox fails to save a page, the only visible result is that
        a tiny down-arrow icon changes from blue to gray. If the previous save
        failed the color simply stays gray. The icon has nothing to do with
        any specific page. The result is that users don't notice. We first
        noticed in early July 2016, but this ccould have started much earlier.

        If a page save operation times out, firefox silently saves the 504
        message. The issue isn't timeouts. Removing the cache-control header
        from responses doesn't appear to help.

        By defauly Mozilla tracks every page you visit.
        (https://support.mozilla.org/en-US/kb/how-does-phishing-and-malware-protection-work)
        We block that tracking. So an attacker may apply other measures.

        If Firefox believes not saving pages is a security measure, it could
        alert users as usual. They don't.

        Example urls:
          * https://www.theguardian.com/us-news/2016/jun/29/us-deadliest-prosecutors-death-penalty-five-attorneys-justice-system
          * https://www.theguardian.com/uk/2013/jun/21/gchq-cables-secret-world-communications-nsa
          * https://yro.slashdot.org/story/16/03/23/1730226/whistleblower-nsa-is-so-overwhelmed-with-data-its-no-longer-effective?sdsrc=rel
          * http://www.vox.com/2016/7/14/12016710/science-challeges-research-funding-peer-review-process

        See:
          * http://kb.mozillazine.org/Unable_to_save_or_download_files
          * https://support.mozilla.org/en-US/questions/1019513
            * Firefox downloads "failed". Have reset FF, been through "downloading problems" trouble doc, and uninstalled/reinstalled FF w/o luck. Safari is able to download.

        Possible mechanisms:
          * http cache-control header
            * removing it does not appear to help
          * http range header
            * firefox requests non-existent range, e.g. "range: bytes=99409-..."
            * removing range and if-range gets full page in, but firefox still doesn't save it

        Workarounds:
          * Cut page text. Paste text in editor. Save as text file.
          * Get html of page (Ctrl-u). Cut html. Paste html in editor. Save file.
    '''

    def filter_response_params(self, params):
        ''' Filter response params to allow saving documents. '''

        remove_params = ['Range',
                         'If-Range',
                         'X-Content-Type-Options',
                         'Cache-Control',
                         ]
        for param in remove_params:
            params = self.remove_param(params, param,
                                       'Removed {} to allow saving documents.'.format(param))

        # get harsh, at least for testing
        upper_case_names = [name.upper() for name in params.keys()]
        for name in upper_case_names:
            if name.startswith('X-'):
                params = self.remove_param(params, name,
                                           'TEST: Removed {} to allow saving documents.'.format(name))
        return params

def proxy(ca_name=CA_NAME, ca_file=CA_FILE, ca_common_name=CA_COMMON_NAME, keys_dir=KEYS_DATA_DIR):
    ''' Configure mitm proxy. '''

    global mitm_proxy

    try:
        log.debug('init proxy')
        if PROFILE:
            ProxyClass = miproxy.proxy.MitmProxy
        else:
            ProxyClass = miproxy.proxy.AsyncMitmProxy
        mitm_proxy = ProxyClass(
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
        pass
        # too noisy
        # mitm_proxy.register_interceptor(LogFilter)
        # mitm_proxy.register_interceptor(LogUrlFilter)
    mitm_proxy.register_interceptor(HtmlFilter)
    mitm_proxy.register_interceptor(TrackingBeaconFilter)
    mitm_proxy.register_interceptor(BreachVulnFilter)
    mitm_proxy.register_interceptor(NoRefererFilter)
    mitm_proxy.register_interceptor(CookieFilter)
    mitm_proxy.register_interceptor(SpoofUserAgentFilter)
    mitm_proxy.register_interceptor(TimeFilter)
    mitm_proxy.register_interceptor(DomainFilter)
    mitm_proxy.register_interceptor(BlobFilter)
    mitm_proxy.register_interceptor(DuckDuckGoNoJSFilter)
    # NOT WORKING
    # mitm_proxy.register_interceptor(AllowSaveFilter)

    log.debug('start proxy')
    try:
        mitm_proxy.serve_forever()
    except Exception as exc:
        log.error(exc)
        log.debug(exc)
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

def profile_proxy():

    def periodic_profile_report():
        # NOT WORKING
        # data does not seem to be written as we go
        log.debug('write periodic profile report')
        timestamped_report = REPORT + '.' + syr.times.timestamp()
        try:
            syr.profile.write_report(DATA, timestamped_report)
            set_profile_timer()
        except Exception as exc:
            log.error(exc)
        else:
            log.debug('wrote periodic profile report to {}'.format(timestamped_report))


    def set_profile_timer():
        log.debug('start profile timer')
        t = threading.Timer(60.0, periodic_profile_report)
        t.start()
        # log.debug('started profile timer')

    import threading
    import syr.profile, syr.times

    # CODESTRING must be an exact copy of the code run when PROFILE is False
    CODESTRING = "proxy()"
    DATA = '/tmp/webfirewall.proxy.profile.data'
    REPORT = '/tmp/webfirewall.proxy.profile.report'

    for path in [DATA, REPORT]:
        if os.path.exists(path):
            os.remove(path)

    set_profile_timer()
    syr.profile.run(CODESTRING, DATA)

def main():

    try:
        log.debug('start main')
        log.debug('HTTP proxy at {}'.format(HTTP_PROXY_URL))

        if PROFILE:
            profile_proxy()

        else:
            proxy()

    except Exception as exc:
        log.error(traceback.format_exc())
    else:
        log.debug('started main')

if __name__ == '__main__':
    ''' run doctests as "python3 -m doctest -v proxy.py" '''
    main()

