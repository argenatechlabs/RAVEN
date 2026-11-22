"""Real local HTTP test target and callback; no production target contacted."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import urllib.parse
import urllib.request

from app.models import ScanStatus, Setting


def _start(handler):
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_all_active_checks_end_to_end(client, db, demo_scan, settings_override):
    seen = []
    baseline_token_count = db.query(Setting).filter(Setting.key.like('raven.oast.%')).count()

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            response = client.get(self.path)
            self.send_response(response.status_code)
            self.end_headers()
        def log_message(self, *_): pass

    callback, callback_thread = _start(CallbackHandler)

    class TargetHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            seen.append((self.path, self.headers.get('Origin'), body))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
        def do_GET(self):
            parts = urllib.parse.urlsplit(self.path)
            if parts.path == '/fetch':
                url = urllib.parse.parse_qs(parts.query)['url'][0]
                with urllib.request.urlopen(url, timeout=2) as result:
                    assert result.status == 204
                self.send_response(200)
            else:
                self.send_response(404)
            self.end_headers()
        def log_message(self, *_): pass

    target, target_thread = _start(TargetHandler)
    try:
        host = f'127.0.0.1:{target.server_port}'
        base = 'http://' + host
        settings_override(oast_public_url=f'http://127.0.0.1:{callback.server_port}',
                          oast_allow_http=True, request_rate_limit=100, scan_headers='', scan_cookie='')
        demo_scan.target_domain = host
        demo_scan.status = ScanStatus.completed
        db.commit()
        payload = {
            'authorized_active': True,
            'csrf': {'url': base+'/csrf?secret=private-query', 'fields': {'csrf_token': 'private-value', 'safe': 'yes'}, 'token_field': 'csrf_token'},
            'upload': {'url': base+'/upload', 'fields': {}, 'file_field': 'file'},
            'ssrf': {'url': base+'/fetch', 'parameter': 'url'},
            'business': {'url': base+'/business', 'fields': {}, 'parameter': 'amount', 'baseline': '10', 'variant': '0'},
        }
        response = client.post(f'/api/scans/{demo_scan.id}/active-checks', json=payload)
        assert response.status_code == 200, response.text
        result = response.json()
        by_kind = {item['category']: item for item in result['items']}
        assert by_kind['csrf']['status'] == 'suspicious'
        assert by_kind['file_upload']['status'] == 'accepted'
        assert by_kind['ssrf']['status'] == 'callback_observed'
        assert by_kind['business_logic']['status'] == 'inconclusive'
        assert len(seen) == 5
        assert b'csrf_token=private-value' in seen[0][2]
        assert b'csrf_token=' not in seen[1][2] and seen[1][1] == 'https://raven-invalid.example'
        assert b'Content-Type: text/plain' in seen[2][2] and b'RAVEN test' in seen[2][2]
        assert b'amount=10' in seen[3][2] and b'amount=0' in seen[4][2]
        serialized = json.dumps(client.get(f'/api/scans/{demo_scan.id}').json())
        assert 'private-value' not in serialized and 'private-query' not in serialized
        db.expire_all()
        assert db.query(Setting).filter(Setting.key.like('raven.oast.%')).count() <= baseline_token_count
        report = client.get(f'/api/scans/{demo_scan.id}/report?format=json')
        assert report.status_code == 200 and len(report.json()['scan']['meta']['active_checks']['items']) == 4
        assert client.get(f'/api/scans/{demo_scan.id}/report?format=pdf').content.startswith(b'%PDF')
    finally:
        target.shutdown(); target.server_close(); target_thread.join()
        callback.shutdown(); callback.server_close(); callback_thread.join()


def test_opt_in_and_scope_are_enforced_before_any_request(client, db, demo_scan, settings_override):
    demo_scan.status = ScanStatus.completed
    demo_scan.target_domain = 'example.com'
    db.commit()
    url = f'/api/scans/{demo_scan.id}/active-checks'
    assert client.post(url, json={'upload': {'url': 'https://example.com/upload', 'file_field': 'file'}}).status_code == 422
    assert client.post(url, json={'authorized_active': True, 'upload': {'url': 'https://example.com.attacker.test/upload', 'file_field': 'file'}}).status_code == 422
    assert client.post(url, json={'authorized_active': True, 'upload': {'url': 'https://example.com:444/upload', 'file_field': 'file'}}).status_code == 422
    assert client.post(url, json={'authorized_active': True, 'csrf': {'url': 'https://example.com/x', 'fields': {}, 'token_field': 'csrf'}}).status_code == 422
    settings_override(oast_public_url='', oast_allow_http=False)
    assert client.post(url, json={'authorized_active': True, 'ssrf': {'url': 'https://example.com/x', 'parameter': 'url'}}).status_code == 422


def test_callback_accepts_only_valid_unexpired_token(client, db):
    import time
    from app.api.active_checks import _key
    import secrets
    token = secrets.token_hex(16)
    db.add(Setting(key=_key(token), value=str(int(time.time()) - 1), is_secret=True))
    db.commit()
    assert client.get('/api/oast/callback/' + token).status_code == 204
    db.expire_all()
    assert db.get(Setting, _key(token)).value.isdigit()
    assert client.get('/api/oast/callback/not-a-token').status_code == 204
    db.delete(db.get(Setting, _key(token)))
    db.commit()


def test_api_key_gate_and_public_token_callback(client, demo_scan, settings_override):
    settings_override(api_key='test-private-key')
    response = client.post(f'/api/scans/{demo_scan.id}/active-checks', json={
        'authorized_active': True, 'upload': {'url': 'https://example.com/upload', 'file_field': 'file'}
    })
    assert response.status_code == 401
    # The callback must be usable by the target without an API key; invalid
    # tokens never expose whether a real token exists.
    assert client.get('/api/oast/callback/not-a-token').status_code == 204


def test_cookie_is_passed_without_scan_headers():
    from app.config import Settings
    value = Settings(scan_headers='', scan_cookie='session=authorized-test')
    assert value.header_map['Cookie'] == 'session=authorized-test'
