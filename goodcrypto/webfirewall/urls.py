'''
    Urls for Web

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-08-05

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

from django.conf.urls import url
from django.core.urlresolvers import reverse

try:
    from goodcrypto.webfirewall import views
except:
    from webfirewall import views

urlpatterns = [

    url(r'^$', views.home, name='home'),
    url(r'certificate/?', views.import_certificate, name='import_certificate'),
    url(r'get_cert/?', views.download_certificate, name='download_certificate'),
    url(r'show_fingerprint/?', views.show_fingerprint, name='show_fingerprint'),

    url(r'^configure/?', views.configure, name='web_configure'),
]

