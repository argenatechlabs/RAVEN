import io
import json
import zipfile

from app.reports.reconstruction import build


def _zip(path, files):
    entries = []
    with zipfile.ZipFile(path, 'w') as z:
        for name, url, mime, body in files:
            z.writestr(name, body)
            entries.append({'file': name, 'url': url, 'content_type': mime})
        z.writestr('manifest.json', json.dumps({'files': entries}))


def test_visual_snapshot_sanitizes_and_beautifies(tmp_path):
    path = tmp_path / 'client-inventory.zip'
    page = 'files/' + 'a'*24 + '.html'
    style = 'files/' + 'b'*24 + '.css'
    image = 'files/' + 'c'*24 + '.png'
    script = 'files/' + 'd'*24 + '.js'
    _zip(path, [
        (page, 'https://example.com/', 'text/html', '<html><head><link rel="stylesheet" href="/a.css"><script src="/a.js"></script></head><body onload="alert(1)"><img src="/logo.png"><a href="https://evil.test">remote</a><form action="/buy" method="post"><input name="price"><button>Buy</button></form></body></html>'),
        (style, 'https://example.com/a.css', 'text/css', '@import "https://evil.test/x.css"; body{background:url(/logo.png)}'),
        (image, 'https://example.com/logo.png', 'image/png', b'fake-png'),
        (script, 'https://example.com/a.js', 'application/javascript', 'function test(){return 42;}'),
    ])
    result = build(str(path))
    with zipfile.ZipFile(io.BytesIO(result)) as z:
        page_text = z.read('index.html').decode()
        assert 'script-src' in page_text and "&#x27;none&#x27;" in page_text
        assert '<script' not in page_text and 'onload' not in page_text and '<form' not in page_text
        assert '<button disabled>' in page_text and '<input name="price" disabled>' in page_text
        assert 'href="https://evil.test"' not in page_text
        assert 'assets/' + 'c'*24 + '.png' in page_text
        css = z.read('assets/' + 'b'*24 + '.css').decode()
        assert 'evil.test' not in css and 'c'*24 + '.png' in css
        js = z.read('analysis/' + 'd'*24 + '.js').decode()
        assert '\n' in js and 'return 42' in js
        assert 'NOT' in z.read('README.txt').decode() or 'not a working application' in z.read('README.txt').decode().lower()


def test_reconstruction_rejects_unsafe_zip_member(tmp_path):
    path = tmp_path / 'bad.zip'
    _zip(path, [('../escape.html', 'https://example.com/', 'text/html', 'no')])
    import pytest
    with pytest.raises(ValueError):
        build(str(path))
