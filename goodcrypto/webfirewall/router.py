'''
    Webfirewall database router.

    Copyright 2015-2016 GoodCrypto
    Last modified: 2016-08-01

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
try:
    from goodcrypto.constants import WEB_DB
except:
    from webfirewall.goodcrypto.constants import WEB_DB
    
class WebRouter(object):
    ''' A router to control all database operations on models in the web app. '''

    def db_for_read(self, model, **hints):
        ''' Attempts to read web models go to Web db. '''
        if self.is_web_db(model):
            return WEB_DB
        else:
            return None

    def db_for_write(self, model, **hints):
        ''' Attempts to write webfirewall models go to Web db. '''
        if self.is_web_db(model):
            return WEB_DB
        else:
            return None

    def allow_relation(self, obj1, obj2, **hints):
        ''' Allow relations if a model in the webfirewall app is involved. '''
        if (self.is_web_db(obj1) or
            self.is_web_db(obj2)):
            return True
        else:
            return None

    def allow_migrate(self, db, app_label, model=None, **hints):
        ''' Make sure the webfirewall apps only appears in the Web database. '''

        if (app_label == WEB_DB):
            return db == WEB_DB
        else:
            return None

    def is_web_db(self, obj):
        ''' Return True if the table is part of the Web database. '''

        return (obj._meta.app_label == WEB_DB)

