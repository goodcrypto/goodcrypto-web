'''
    Admin for GoodCrypto Webfirewall.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-08-01
'''
from django.contrib import admin
from django_singleton_admin.admin import SingletonAdmin

try:
    from goodcrypto.webfirewall import models
    from goodcrypto.webfirewall.forms import OptionsAdminForm
except:
    from webfirewall import models
    from webfirewall.forms import OptionsAdminForm


"""
class Options(SingletonAdmin):
    form = OptionsAdminForm

    fieldsets = (
        (None, {
            'fields': (
                'tor_middle_relay',
            )
        }),
    )
admin.site.register(models.Options, Options)
"""
