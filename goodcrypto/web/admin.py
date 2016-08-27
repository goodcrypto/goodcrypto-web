'''
    Admin for GoodCrypto Web.

    Copyright 2014 GoodCrypto
    Last modified: 2015-09-17
'''
from django.contrib import admin

from goodcrypto.web import models
from goodcrypto.web.forms import OptionsAdminForm
from django_singleton_admin.admin import SingletonAdmin


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
