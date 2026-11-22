"""Bounded, same-origin client-side inventory and untrusted source archive.

Only public GET responses on discovered hosts are collected. No JavaScript is
executed, forms are never submitted, and source maps are not treated as proof
of a vulnerability. Archive files must never be served from the app origin.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import zipfile
from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit

import httpx

MAX_FILES = 30
MAX_BYTES = 8 * 1024 * 1024
MAX_FILE = 1024 * 1024
MAX_SECONDS = 30
_PATH = re.compile(r'''["'](/(?:api|graphql|v[0-9]+|rest)/?[^"'\s<>]{0,180})["']''', re.I)
_MAP = re.compile(r'[#@]\s*sourceMappingURL=([^\s*]+)')


def _origin(url):
    try:
        p = urlsplit(url)
        if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
            return None
        return (p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == 'https' else 80))
    except ValueError:
        return None


def _normal(url):
    return urldefrag(url)[0]


class _HTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.assets = []
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ('script', 'link', 'img'):
            url = a.get('src') if tag != 'link' else a.get('href')
            if url:
                self.assets.append(url)
        if tag == 'form':
            self.current = {'action': a.get('action') or '', 'method': (a.get('method') or 'get').upper()[:20], 'fields': []}
            self.forms.append(self.current)
        if tag in ('input', 'select', 'textarea') and self.current is not None and a.get('name'):
            self.current['fields'].append(a['name'][:100])

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None


def _archive_name(url, content_type):
    # Content-addressed names avoid path traversal, query collisions and ZIP slip.
    path = urlsplit(url).path.lower()
    ext = next((e for e in ('.html', '.js', '.mjs', '.css', '.json', '.map', '.svg', '.png', '.jpg', '.jpeg', '.woff2', '.txt', '.xml') if path.endswith(e)), '')
    if not ext:
        ext = '.html' if 'html' in content_type else '.bin'
    return 'files/' + hashlib.sha256(url.encode()).hexdigest()[:24] + ext


def run(ctx, alive, endpoints):
    """Return metadata and an archive. Nothing outside the exact host:port set is requested."""
    result = {'status': 'skipped', 'files': [], 'forms': [], 'api_paths': [], 'parameters': [],
              'source_maps': [], 'limits': {'files': MAX_FILES, 'bytes': MAX_BYTES, 'seconds': MAX_SECONDS},
              'archive_available': False}
    if ctx.settings.demo_mode or ctx.expired() or not alive:
        return result
    # Authority is based on the live hosts, not on links returned by the target.
    authorities = set()
    for host in alive:
        for scheme in ('http', 'https'):
            origin = _origin(f'{scheme}://{host.subdomain}/')
            if origin:
                authorities.add(origin)
    urls = [_normal(e.url) for e in endpoints if _origin(e.url) in authorities]
    # Prioritize JS and documents; never follow arbitrary JS-discovered API paths.
    seeds = []
    files = [u for u in urls if urlsplit(u).path.lower().endswith(('.js', '.mjs', '.css', '.map', '.json'))]
    pages = [u for u in urls if not urlsplit(u).query and u not in files]
    seed_origins = {_origin(u) for u in urls if _origin(u)}
    if not seed_origins:
        # A crawler may discover no links even though the landing page is live.
        # Prefer the port observed by the liveness probe.
        for host in alive:
            scheme = 'https' if 443 in host.ports else 'http'
            origin = _origin(f'{scheme}://{host.subdomain}/')
            if origin:
                seed_origins.add(origin)
    for origin in sorted(seed_origins):
        scheme, host, port = origin
        authority = f'[{host}]' if ':' in host else host
        if port != (443 if scheme == 'https' else 80):
            authority += f':{port}'
        seeds.extend(f'{scheme}://{authority}{p}' for p in ('/', '/robots.txt', '/sitemap.xml'))
    queue = deque(seeds + files + pages)
    seen = set()
    started = time.monotonic()
    total = 0
    last_request = 0.0
    source_maps = []
    api_paths = set()
    params = set()
    for url in urls[:500]:
        params.update(k[:100] for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True))
    archive_path = os.path.join(ctx.workdir, 'client-inventory.zip')
    os.makedirs(ctx.workdir, exist_ok=True)
    with httpx.Client(follow_redirects=False, verify=False, trust_env=False,
                      headers={'User-Agent': 'RAVEN-Pentest/1.0', 'Accept': '*/*'}) as client, \
            zipfile.ZipFile(archive_path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        while queue and len(seen) < MAX_FILES and total < MAX_BYTES and not ctx.expired() and time.monotonic() - started < MAX_SECONDS:
            url = _normal(queue.popleft())
            if url in seen or _origin(url) not in authorities or urlsplit(url).query:
                continue
            seen.add(url)
            wait = max(0.0, last_request + 1 / max(1, ctx.settings.request_rate_limit) - time.monotonic())
            if wait:
                time.sleep(min(wait, max(0.0, MAX_SECONDS - (time.monotonic() - started))))
            if ctx.expired() or time.monotonic() - started >= MAX_SECONDS:
                break
            last_request = time.monotonic()
            remaining = max(0.1, min(4.0, MAX_SECONDS - (time.monotonic() - started)))
            if ctx.deadline is not None:
                remaining = max(0.1, min(remaining, ctx.deadline - time.monotonic()))
            try:
                client.cookies.clear()
                with client.stream('GET', url, timeout=remaining) as response:
                    # Redirects may leave scope. Record, never follow them.
                    if response.status_code != 200:
                        continue
                    content_type = response.headers.get('content-type', '').split(';')[0].lower()
                    chunks = []
                    size = 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > MAX_FILE or total + size > MAX_BYTES or ctx.expired() or time.monotonic() - started >= MAX_SECONDS:
                            chunks = []
                            break
                        chunks.append(chunk)
                    if not chunks:
                        continue
                    data = b''.join(chunks)
            except (httpx.HTTPError, ValueError):
                continue
            total += len(data)
            filename = _archive_name(url, content_type)
            archive.writestr(filename, data)
            result['files'].append({'url': url, 'file': filename, 'content_type': content_type, 'bytes': len(data)})
            text = data.decode('utf-8', errors='replace')
            path = urlsplit(url).path.lower()
            if 'html' in content_type or path.endswith(('.html', '.htm')):
                parser = _HTML()
                try:
                    parser.feed(text)
                except Exception:
                    continue
                for form in parser.forms[:30]:
                    result['forms'].append({'page': url, 'action': urljoin(url, form['action']), 'method': form['method'], 'fields': form['fields'][:30]})
                for asset in parser.assets[:100]:
                    absolute = _normal(urljoin(url, asset))
                    if _origin(absolute) in authorities:
                        queue.append(absolute)
            if path.endswith(('.js', '.mjs')) or 'javascript' in content_type:
                api_paths.update(_PATH.findall(text)[:100])
                for ref in _MAP.findall(text)[-2:]:
                    absolute = _normal(urljoin(url, ref))
                    if _origin(absolute) in authorities and not urlsplit(absolute).query:
                        queue.appendleft(absolute)
            if 'json' in content_type or path.endswith('.json'):
                try:
                    spec = json.loads(text)
                    if isinstance(spec, dict) and ('openapi' in spec or 'swagger' in spec) and isinstance(spec.get('paths'), dict):
                        api_paths.update(str(p)[:180] for p in list(spec['paths'])[:200])
                except (ValueError, TypeError):
                    pass
            if path.endswith('.map') or 'json' in content_type and '"sources"' in text[:1000]:
                try:
                    mapping = json.loads(text)
                    sources = mapping.get('sources', []) if isinstance(mapping, dict) else []
                    embedded = mapping.get('sourcesContent') or []
                    if not isinstance(embedded, list):
                        embedded = []
                    for source in embedded[:100]:
                        if isinstance(source, str):
                            api_paths.update(_PATH.findall(source)[:100])
                    source_maps.append({'url': url, 'sources': [str(s)[:200] for s in sources[:100]],
                                        'embedded_sources': sum(isinstance(s, str) for s in embedded[:100])})
                except (ValueError, TypeError, AttributeError):
                    pass
        result['status'] = 'partial' if queue or ctx.expired() else 'completed'
        result['api_paths'] = sorted(api_paths)[:200]
        result['parameters'] = sorted(params)[:200]
        result['source_maps'] = source_maps[:30]
        result['forms'] = result['forms'][:100]
        result['archive_available'] = bool(result['files'])
        archive.writestr('manifest.json', json.dumps(result, ensure_ascii=False, indent=2))
        archive.writestr('README.txt', 'Untrusted source snapshot, NOT a working site clone. Do not execute or host these files on a trusted origin. It may contain secrets or personal data. Server code, database and dynamic behaviour are not included. See manifest.json for original URLs.\n')
    return result
