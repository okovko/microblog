import json, requests
from flask_babel import _
from app import app

def translate(text, src_lang, dst_lang):
    if 'MS_TRANSLATOR_KEY' not in app.config or \
       not app.config['MS_TRANSLATOR_KEY']:
        return _('Error: the translation service is not properly configured.')
    auth = {'Ocp-Apim-Subscription-Key' : app.config['MS_TRANSLATOR_KEY']}
    r = requests.get('https://api.microsofttranslator.com/v2/Ajax.svc'
                     '/Translate?text={}&from={}&to={}'.format(
                         text, src_lang, dst_lang),
                     headers = auth)
    if r.status_code != 200:
        return _('Error: the translation service failed.')
    return json.loads(r.content.decode('utf-8-sig'))
