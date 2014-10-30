'''
    Internationalized messages used in GoodCrypto Web.

    Copyright 2014 GoodCrypto
    Last modified: 2014-08-30

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

from goodcrypto.utils.internationalize import translate

# web/models.py
WEB_OPTIONS_NAME = translate('options')
SHOW_IMAGES_FIELD = translate('Show images')
SHOW_IMAGES_FIELD_HELP = translate('It is strongly recommeneded that you disable images as there are known security issues when displayed.')
WEB_US_STANDARDS_FIELD = translate('Use US standards?')
WEB_US_STANDARDS_FIELD_HELP = translate("Use the standards supported by US government. We strongly recommend you set this to False.")

# web/forms.py
ONLY_ONE_OPTION = translate('You may only have one Options record. Either change the current record or delete it before adding.')

