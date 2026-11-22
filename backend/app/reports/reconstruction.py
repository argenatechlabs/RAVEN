"""Build an inert offline visual reconstruction from a bounded source archive.

This is not a server-side clone. Untrusted scripts and forms are disabled and
never executed here. Archive output is generated from known hash names only.
"""
from __future__ import annotations

import html
import io
import json
import re
import zipfile
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

import jsbeautifier

_NAME = re.compile(r'^files/[a-f0-9]{24}\.[a-z0-9]+$')
_CSS_URL = re.compile(r'''url\(\s*(['"]?)(.*?)\1\s*\)''', re.I)
_IMPORT = re.compile(r'@import\s+[^;]*(?:;|$)', re.I)
_VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}
_SKIP = {'script', 'iframe', 'object', 'embed', 'base', 'noscript', 'video', 'audio'}
_CSP = "default-src 'none'; script-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'"


def _css(text, url, mapping, css_file=False):
    text = _IMPORT.sub('', text)
    def replace(match):
        target = urldefrag(urljoin(url, match.group(2).strip()))[0]
        local = mapping.get(target, '')
        if css_file and local.startswith('assets/'):
            local = local.removeprefix('assets/')
        return 'url("' + local + '")'
    return _CSS_URL.sub(replace, text)


class _SnapshotHTML(HTMLParser):
    def __init__(self, url, mapping):
        super().__init__(convert_charrefs=False)
        self.url, self.mapping = url, mapping
        self.out = []
        self.skip_depth = 0
        self.in_style = False

    def handle_decl(self, decl):
        if decl.lower() == 'doctype html':
            self.out.append('<!DOCTYPE html>')

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self.skip_depth:
            if tag not in _VOID:
                self.skip_depth += 1
            return
        if tag in _SKIP:
            if tag not in _VOID:
                self.skip_depth = 1
            return
        if tag == 'form':
            self.out.append('<div class="raven-disabled-form">')
            return
        attrs = dict(attrs)
        if tag == 'meta' and ('http-equiv' in attrs or 'charset' in attrs):
            return
        if tag == 'link' and (attrs.get('rel') or '').lower() != 'stylesheet':
            return
        safe = []
        for key, value in attrs.items():
            key = key.lower()
            value = value or ''
            if (not re.fullmatch(r'[a-z_:][a-z0-9:_.-]*', key) or key.startswith('on') or
                    key in {'srcset', 'formaction', 'action', 'ping', 'integrity', 'nonce', 'crossorigin',
                            'xlink:href', 'background', 'srcdoc', 'data', 'manifest', 'poster'}):
                continue
            if key == 'style':
                value = _css(value, self.url, self.mapping)
            if key in ('src', 'href'):
                target = urldefrag(urljoin(self.url, value))[0]
                value = self.mapping.get(target, '')
                if not value:
                    continue
            safe.append(f' {key}="{html.escape(value, quote=True)}"')
        if tag in ('input', 'select', 'textarea', 'button'):
            safe.append(' disabled')
        self.out.append('<' + tag + ''.join(safe) + '>')
        if tag == 'style':
            self.in_style = True

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.skip_depth:
            self.skip_depth -= 1
            return
        if tag in _SKIP or tag in _VOID:
            return
        if tag == 'form':
            self.out.append('</div>')
            return
        if tag == 'style':
            self.in_style = False
        self.out.append(f'</{tag}>')

    def handle_data(self, data):
        if not self.skip_depth:
            self.out.append(_css(data, self.url, self.mapping) if self.in_style else data)

    def handle_entityref(self, name):
        if not self.skip_depth:
            self.out.append(f'&{name};')

    def handle_charref(self, name):
        if not self.skip_depth:
            self.out.append(f'&#{name};')


def build(archive_path: str) -> bytes:
    """Return ZIP containing static pages, local assets and formatted JS.

    Enforce independent compressed archive extraction limits even though the
    input archive is generated internally. Never use original URL as a path.
    """
    with zipfile.ZipFile(archive_path) as source:
        info = source.getinfo('manifest.json')
        if info.file_size > 512_000:
            raise ValueError('manifest çok büyük')
        manifest = json.loads(source.read(info))
        files = manifest.get('files', [])[:30]
        validated = []
        total = 0
        for item in files:
            name = item.get('file', '')
            if not _NAME.fullmatch(name) or not isinstance(item.get('url'), str):
                continue
            entry = source.getinfo(name)
            total += entry.file_size
            if entry.file_size > 1024 * 1024 or total > 8 * 1024 * 1024:
                raise ValueError('arşiv boyut sınırı aşıldı')
            validated.append((item, source.read(entry)))
    pages = [(i, b) for i, b in validated if 'html' in i.get('content_type', '') or i['file'].endswith('.html')]
    if not pages:
        raise ValueError('yeniden oluşturulacak HTML sayfası yok')
    pages.sort(key=lambda pair: (urlsplit(pair[0]['url']).path not in ('', '/'), pair[0]['url']))
    mapping = {}
    for index, (item, _) in enumerate(pages):
        mapping[item['url']] = 'index.html' if index == 0 else 'page_' + item['file'][6:-5] + '.html'
    allowed_assets = ('.css', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.woff', '.woff2', '.ttf')
    for item, _ in validated:
        if item['file'].endswith(allowed_assets):
            mapping[item['url']] = 'assets/' + item['file'].split('/', 1)[1]
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as target:
        for item, content in pages:
            parser = _SnapshotHTML(item['url'], mapping)
            parser.feed(content.decode('utf-8', errors='replace'))
            prefix = '<meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="' + html.escape(_CSP, quote=True) + '">'
            target.writestr(mapping[item['url']], prefix + ''.join(parser.out))
        formatted = []
        for item, content in validated:
            filename = item['file']
            if filename.endswith(allowed_assets):
                asset = mapping[item['url']]
                if filename.endswith('.css'):
                    content = _css(content.decode('utf-8', errors='replace'), item['url'], mapping, True).encode()
                target.writestr(asset, content)
            elif filename.endswith(('.js', '.mjs')) and len(formatted) < 10 and len(content) <= 512 * 1024:
                try:
                    formatted_text = jsbeautifier.beautify(content.decode('utf-8', errors='replace'))
                except Exception:
                    continue
                output_name = 'analysis/' + filename.split('/', 1)[1]
                target.writestr(output_name, formatted_text)
                formatted.append({'url': item['url'], 'file': output_name})
        target.writestr('manifest.json', json.dumps({'pages_and_assets': mapping, 'formatted_javascript': formatted}, ensure_ascii=False, indent=2))
        target.writestr('README.txt', 'Offline visual snapshot ONLY. Not a working application: JavaScript, forms and server operations are disabled. Pages and formatting are best-effort. Do not host on a trusted origin. Source files can contain secrets and personal data. See manifest.json.\n')
    return output.getvalue()
