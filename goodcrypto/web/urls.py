'''
    Urls for Web
   
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-09

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

from django.conf.urls import *
from django.core.urlresolvers import reverse 

from goodcrypto.web import views

urlpatterns = patterns('',

    url(r'^$', views.home, name='home'),
    url(r'get_cert/?', views.download_certficate, name='download_certficate'),
    url(r'show_fingerprint/?', views.show_fingerprint, name='show_fingerprint'),

    url(r'^configure/?', views.configure, name='web_configure'),
    url(r'^api/?', views.api, name='web_api'),
)

