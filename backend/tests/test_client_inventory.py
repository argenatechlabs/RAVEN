from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
import zipfile
from types import SimpleNamespace

from app.scanners.client_inventory import run, _origin
from app.scanners.types import EndpointResult, SubdomainResult


def test_origin_rejects_userinfo_and_invalid_port():
    assert _origin('https://site.example@evil.example/a') is None
    assert _origin('http://example.org:999999/') is None
    assert _origin('http://EXAMPLE.org/a') == ('http', 'example.org', 80)


def test_inventory_scopes_requests_and_collects_source_maps(tmp_path):
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == '/':
                content = b'''<html><script src="/app.js"></script><link rel="stylesheet" href="/style.css"><img src="http://localhost:1/evil.png"><form action="/submit" method="post"><input name="email"></form></html>'''
                ctype = 'text/html'
            elif self.path == '/style.css':
                content = b'body{background:url(/background.png)}'
                ctype = 'text/css'
            elif self.path == '/background.png':
                content = b'png'
                ctype = 'image/png'
            elif self.path == '/app.js':
                content = b'''const u="/api/users";\n//# sourceMappingURL=app.js.map'''
                ctype = 'application/javascript'
            elif self.path == '/app.js.map':
                content = json.dumps({'version': 3, 'sources': ['src/app.ts'], 'sourcesContent': ['const hidden = "/api/from-source-map"']}).encode()
                ctype = 'application/json'
            elif self.path == '/openapi.json':
                content = json.dumps({'openapi': '3.0.0', 'paths': {'/api/items': {}}}).encode()
                ctype = 'application/json'
            elif self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', 'http://127.0.0.1:1/blocked')
                self.end_headers()
                return
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f'http://127.0.0.1:{server.server_port}'
        ctx = SimpleNamespace(workdir=str(tmp_path), settings=SimpleNamespace(demo_mode=False, request_rate_limit=100),
                              deadline=time.monotonic() + 15, expired=lambda: False)
        hosts = [SubdomainResult(subdomain=f'127.0.0.1:{server.server_port}')]
        endpoints = [EndpointResult(base + '/'), EndpointResult(base + '/openapi.json'),
                     EndpointResult(base + '/redirect'), EndpointResult(base + '/search?q=x'),
                     EndpointResult('http://localhost:1/evil.js', is_js=True)]
        result = run(ctx, hosts, endpoints)
        assert result['archive_available']
        assert {'/api/users', '/api/items', '/api/from-source-map'} <= set(result['api_paths'])
        assert result['parameters'] == ['q']
        assert result['forms'][0]['fields'] == ['email']
        assert result['source_maps'][0]['sources'] == ['src/app.ts']
        assert result['source_maps'][0]['embedded_sources'] == 1
        assert '/submit' not in hits
        assert '/background.png' in hits
        with zipfile.ZipFile(tmp_path / 'client-inventory.zip') as archive:
            manifest = json.loads(archive.read('manifest.json'))
            assert manifest['files']
            assert all(name.startswith('files/') and '..' not in name for name in archive.namelist() if name.startswith('files/'))
            assert 'NOT a working site clone' in archive.read('README.txt').decode()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_inventory_archive_api_and_pipeline(db, demo_scan, settings_override, monkeypatch, client, tmp_path):
    from app.core import pipeline
    from app.models import Scan, ScanStatus
    from app.scanners.common import EngineReport

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != '/':
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><form action="/save" method="post"><input name="name"></form></html>')

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = f'127.0.0.1:{server.server_port}'
        report = EngineReport(engine='test', detail='test')
        monkeypatch.setattr(pipeline.recon, 'run', lambda ctx: ([host], report))
        monkeypatch.setattr(pipeline.tech, 'run', lambda ctx, subs: ([SubdomainResult(subdomain=host)], report))
        monkeypatch.setattr(pipeline.tls, 'run', lambda ctx, alive: ([], report))
        monkeypatch.setattr(pipeline.crawler, 'run', lambda ctx, alive: ([EndpointResult(f'http://{host}/')], report))
        monkeypatch.setattr(pipeline.vuln, 'run', lambda ctx, alive, endpoints, extra_findings: ([], report))
        monkeypatch.setattr(pipeline.secrets, 'run', lambda ctx, endpoints: ([], report))
        settings = settings_override(demo_mode=False, data_dir=str(tmp_path), request_rate_limit=100, ai_provider='local')
        pipeline.ScanPipeline(demo_scan.id, settings).run()
        db.expire_all()
        scan = db.get(Scan, demo_scan.id)
        assert scan.status == ScanStatus.completed
        assert scan.meta['client_inventory']['forms'][0]['fields'] == ['name']
        assert any(item['category'] == 'csrf' and not item['tested'] for item in scan.meta['client_inventory']['manual_review'])
        response = client.get(f'/api/scans/{scan.id}/client-inventory/archive')
        assert response.status_code == 200
        assert response.headers['content-type'] == 'application/zip'
        assert response.content.startswith(b'PK')
        reconstructed = client.get(f'/api/scans/{scan.id}/client-inventory/reconstruction')
        assert reconstructed.status_code == 200 and reconstructed.content.startswith(b'PK')
        import io
        with zipfile.ZipFile(io.BytesIO(reconstructed.content)) as z:
            assert 'index.html' in z.namelist()
            assert b'disabled' in z.read('index.html')
        assert client.get('/api/scans/999999/client-inventory/archive').status_code == 404
        pdf = client.get(f'/api/scans/{scan.id}/report?format=pdf')
        assert pdf.status_code == 200 and pdf.content.startswith(b'%PDF')
        report_json = client.get(f'/api/scans/{scan.id}/report?format=json').json()
        assert report_json['scan']['meta']['client_inventory']['archive_available']
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
