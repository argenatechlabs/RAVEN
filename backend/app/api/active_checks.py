"""Explicitly authorised, operator-directed active checks.

No discovered form is submitted automatically. Each URL and safe test value
must be supplied by the operator for this single run. Responses are recorded as
observations, not inferred exploitability. Callback tokens are short-lived.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.config import settings
from app.core.security import api_write_limit
from app.database import SessionLocal, get_db
from app.models import Scan, ScanStatus, Setting

router = APIRouter()
callback_router = APIRouter()
_KEY = re.compile(r'^[A-Za-z0-9_.\-\[\]]{1,80}$')
_TOKEN = re.compile(r'^[a-f0-9]{32}$')
_TOKEN_PREFIX = 'raven.oast.'


class Fields(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    fields: Dict[str, str] = Field(default_factory=dict)

    @model_validator(mode='after')
    def validate_fields(self):
        if len(self.fields) > 20 or any(not _KEY.fullmatch(k) or len(v) > 2000 for k, v in self.fields.items()):
            raise ValueError('Geçersiz form alanı')
        return self


class CsrfCheck(Fields):
    token_field: str = Field(min_length=1, max_length=80)


class UploadCheck(Fields):
    file_field: str = Field(min_length=1, max_length=80)


class SsrfCheck(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    parameter: str = Field(min_length=1, max_length=80)


class BusinessCheck(Fields):
    parameter: str = Field(min_length=1, max_length=80)
    baseline: str = Field(max_length=200)
    variant: str = Field(max_length=200)


class ActiveChecksRequest(BaseModel):
    authorized_active: bool = False
    csrf: Optional[CsrfCheck] = None
    upload: Optional[UploadCheck] = None
    ssrf: Optional[SsrfCheck] = None
    business: Optional[BusinessCheck] = None

    @model_validator(mode='after')
    def validate_config(self):
        if not self.authorized_active:
            raise ValueError('Aktif ve durum değiştirebilen testler için ayrı onay gerekli')
        if not any((self.csrf, self.upload, self.ssrf, self.business)):
            raise ValueError('En az bir test seçin')
        for key in (self.csrf.token_field if self.csrf else '',
                    self.upload.file_field if self.upload else '',
                    self.ssrf.parameter if self.ssrf else '',
                    self.business.parameter if self.business else ''):
            if key and not _KEY.fullmatch(key):
                raise ValueError('Geçersiz parametre adı')
        if self.csrf and not self.csrf.fields.get(self.csrf.token_field):
            raise ValueError('CSRF kontrolü için form alanları boş olmayan token değerini içermeli')
        if self.business and self.business.baseline == self.business.variant:
            raise ValueError('İş mantığı normal ve test değerleri farklı olmalı')
        return self


def _scope(url: str, target: str) -> str:
    """Only the exact scan host and its explicitly configured/default ports."""
    try:
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
            raise ValueError()
        p = urlsplit(url)
        t = urlsplit('//'+target)
        if (p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password
                or p.fragment or p.hostname.lower() != (t.hostname or '').lower()):
            raise ValueError()
        port = p.port or (443 if p.scheme == 'https' else 80)
        if (t.port is not None and port != t.port) or (t.port is None and port not in (80, 443)):
            raise ValueError()
    except ValueError:
        raise HTTPException(status_code=422, detail='Test URL’si taranan host ve port ile aynı olmalı')
    return url


def _location(url: str) -> str:
    """Do not persist query strings; they may contain credentials."""
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, '', ''))


def _callback_base() -> Optional[str]:
    value = settings.oast_public_url.strip().rstrip('/')
    if not value:
        return None
    try:
        p = urlsplit(value)
        if (p.scheme not in (('http', 'https') if settings.oast_allow_http else ('https',))
                or not p.hostname or p.username or p.password or p.query or p.fragment):
            return None
        _ = p.port
    except ValueError:
        return None
    return value


def _key(token: str) -> str:
    return _TOKEN_PREFIX + hashlib.sha256(token.encode()).hexdigest()


def _create_token() -> str:
    token = secrets.token_hex(16)
    with SessionLocal() as db:
        # Recover expired records after a worker crash without deleting tokens
        # belonging to concurrent active runs.
        db.execute(delete(Setting).where(
            Setting.key.startswith(_TOKEN_PREFIX),
            Setting.updated_at < datetime.utcnow() - timedelta(minutes=10),
        ))
        db.add(Setting(key=_key(token), value=str(int(time.time()) + 120), is_secret=True))
        db.commit()
    return token


def _remove_token(token: str) -> None:
    with SessionLocal() as db:
        row = db.get(Setting, _key(token))
        if row:
            db.delete(row)
            db.commit()


def _received(token: str) -> bool:
    with SessionLocal() as db:
        row = db.get(Setting, _key(token))
        return bool(row and row.value and row.value.startswith('seen:'))


@callback_router.get('/api/oast/callback/{token}', include_in_schema=False)
def callback(token: str, db: Session = Depends(get_db)):
    # No API key: a target must reach this high-entropy, short-lived endpoint.
    # All responses are identical; do not store the request, IP, or headers.
    if _TOKEN.fullmatch(token):
        row = db.get(Setting, _key(token))
        if row and row.value and row.value.isdigit() and int(row.value) >= time.time():
            row.value = 'seen:' + row.value
            db.commit()
    return Response(status_code=204, headers={'Cache-Control': 'no-store'})


def _request(client: httpx.Client, method: str, url: str, **kwargs):
    try:
        # Do not buffer unbounded target responses or follow redirects.
        with client.stream(method, url, follow_redirects=False, timeout=5.0, **kwargs) as response:
            return response.status_code
    except httpx.HTTPError:
        return None


def _query(url: str, name: str, value: str) -> str:
    p = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(pairs), ''))


def _ok(status: Optional[int]) -> bool:
    return status is not None and 200 <= status < 300


@router.post('/api/scans/{scan_id}/active-checks', dependencies=[Depends(api_write_limit)])
def run_active_checks(scan_id: int, payload: ActiveChecksRequest, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail='Tarama bulunamadı')
    if not scan.authorized or scan.status != ScanStatus.completed:
        raise HTTPException(status_code=409, detail='Yetkili ve tamamlanmış bir tarama gerekli')
    for check in (payload.csrf, payload.upload, payload.ssrf, payload.business):
        if check:
            _scope(check.url, scan.target_domain)
    callback_base = _callback_base() if payload.ssrf else None
    if payload.ssrf and not callback_base:
        raise HTTPException(status_code=422, detail='SSRF için OAST_PUBLIC_URL yapılandırılmalı (HTTPS)')

    results = []
    # Headers/cookies are scoped to exactly one validated host. Do not retain
    # target-set cookies between requests or automatically follow redirects.
    with httpx.Client(verify=False, trust_env=False, headers=settings.header_map,
                      follow_redirects=False) as client:
        last_request = 0.0
        def request(method, url, **kwargs):
            nonlocal last_request
            interval = 1.0 / max(1, settings.request_rate_limit)
            wait = last_request + interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            last_request = time.monotonic()
            return _request(client, method, url, **kwargs)

        if payload.csrf:
            c = payload.csrf
            baseline = request('POST', c.url, data=c.fields)
            # Preserve only explicitly configured cookie headers, never cookies
            # set by a previous request to this target.
            client.cookies.clear()
            forged = {k: v for k, v in c.fields.items() if k != c.token_field}
            mutated = request('POST', c.url, data=forged,
                               headers={'Origin': 'https://raven-invalid.example'})
            results.append({'category': 'csrf', 'url': _location(c.url),
                            'status': 'suspicious' if _ok(baseline) and _ok(mutated) else 'inconclusive',
                            'tested': True, 'baseline_status': baseline, 'test_status': mutated,
                            'detail': 'İki POST gönderildi. HTTP durumu tek başına durum değişikliğini, tarayıcı çerez politikasını veya CSRF açığını kanıtlamaz.'})
        if payload.upload:
            c = payload.upload
            client.cookies.clear()
            marker = secrets.token_hex(8)
            status = request('POST', c.url, data=c.fields,
                              files={c.file_field: (f'raven-{marker}.txt', f'RAVEN test {marker}\n'.encode(), 'text/plain')})
            results.append({'category': 'file_upload', 'url': _location(c.url),
                            'status': 'accepted' if _ok(status) else 'inconclusive', 'tested': True,
                            'test_status': status,
                            'detail': 'Zararsız bir metin dosyası gönderildi. Başarılı HTTP yanıtı dosyanın kaydedildiğini veya açık olduğunu kanıtlamaz; test artığı oluşmuş olabilir.'})
        if payload.ssrf:
            c = payload.ssrf
            client.cookies.clear()
            token = _create_token()
            try:
                callback_url = f'{callback_base}/api/oast/callback/{token}'
                status = request('GET', _query(c.url, c.parameter, callback_url))
                deadline = time.monotonic() + 5
                seen = _received(token)
                while not seen and time.monotonic() < deadline:
                    time.sleep(0.25)
                    seen = _received(token)
                results.append({'category': 'ssrf', 'url': _location(c.url),
                                'status': 'callback_observed' if seen else 'inconclusive', 'tested': True,
                                'test_status': status,
                                'detail': ('Tek kullanımlık adrese HTTP geri çağrısı gözlendi; kaynağı ve güvenlik etkisi ayrıca doğrulanmalı.'
                                           if seen else '5 saniye içinde geri çağrı görülmedi; bu durum SSRF olmadığını kanıtlamaz.')})
            finally:
                _remove_token(token)
        if payload.business:
            c = payload.business
            client.cookies.clear()
            first = {**c.fields, c.parameter: c.baseline}
            baseline = request('POST', c.url, data=first)
            client.cookies.clear()
            second = {**c.fields, c.parameter: c.variant}
            variant = request('POST', c.url, data=second)
            results.append({'category': 'business_logic', 'url': _location(c.url), 'status': 'inconclusive',
                            'tested': True, 'baseline_status': baseline, 'test_status': variant,
                            'detail': 'İki POST gönderildi. HTTP kodları iş kuralı ihlalini veya kalıcı durum değişikliğini kanıtlamaz.'})
    entry = {'timestamp': datetime.utcnow().isoformat(), 'items': results}
    scan.meta = {**(scan.meta or {}), 'active_checks': entry}
    db.commit()
    return entry
