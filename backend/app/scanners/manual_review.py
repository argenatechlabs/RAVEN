"""Non-invasive review leads, not confirmed vulnerability findings.

Never submit forms, send upload payloads, trigger fetches to external servers,
or change business state. Absence of a field is not proof of a CSRF flaw.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

_CSRF = re.compile(r'csrf|xsrf|authenticity|requestverification|antiforgery', re.I)
_SSRF = re.compile(r'^(url|uri|endpoint|callback|webhook|target|host|proxy|fetch|image_url|feed)$', re.I)
_BUSINESS = re.compile(r'^(price|amount|total|discount|coupon|balance|quantity|role|is_admin|userid|user_id)$', re.I)


def run(inventory, endpoints):
    result = []
    def add(kind, location, reason):
        if len(result) < 100:
            result.append({'category': kind, 'url': str(location)[:1000], 'reason': reason,
                           'status': 'manual_review', 'tested': False})

    for form in inventory.get('forms', [])[:100]:
        fields = form.get('fields') or []
        types = form.get('field_types') or []
        url = form.get('page', '')
        if form.get('method', 'GET').upper() not in ('GET', 'HEAD'):
            if any(_CSRF.search(str(name)) for name in fields):
                add('csrf', url, 'Token benzeri alan görüldü; sunucu doğrulaması, header ve çerez koruması test edilmedi. Form gönderilmedi.')
            else:
                add('csrf', url, 'Durum değiştirebilecek formda bilinen token alanı görülmedi. Header, çerez ve sunucu kontrolü ayrıca doğrulanmalı; form gönderilmedi.')
        if 'file' in types:
            add('file_upload', url, 'Dosya alanı gözlendi; dosya gönderilmedi, uzantı ve içerik doğrulaması sınanmadı.')
        if any(_SSRF.match(str(name)) for name in fields):
            add('ssrf', url, 'URL/hedef alanı görüldü; sunucunun istek yapıp yapmadığı test edilmedi.')
        if any(_BUSINESS.match(str(name)) for name in fields):
            add('business_logic', url, 'Fiyat, rol veya nesne tanımlayıcısı benzeri alan gözlendi; yetki ve iş kuralı doğrulanmadı.')
    for endpoint in endpoints[:500]:
        url = endpoint.url
        names = [name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
        if any(_SSRF.match(name) for name in names):
            add('ssrf', url.split('?', 1)[0], 'URL/hedef parametresi görüldü; sunucu tarafı istek doğrulanmadı.')
        if any(_BUSINESS.match(name) for name in names):
            add('business_logic', url.split('?', 1)[0], 'İş mantığı açısından incelenebilecek parametre görüldü; değişiklik yapılmadı.')
    return result
