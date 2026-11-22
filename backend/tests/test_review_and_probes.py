from types import SimpleNamespace

import httpx

from app.scanners.manual_review import run
from app.scanners.types import EndpointResult
from app.scanners.vuln import _candidate_param_urls, _parameter_checks


def test_manual_reviews_are_explicitly_not_test_results():
    inventory = {'forms': [
        {'page': 'https://site.test/upload', 'method': 'POST', 'fields': ['target', 'price'], 'field_types': ['file']},
        {'page': 'https://site.test/protected', 'method': 'POST', 'fields': ['csrf_token'], 'field_types': ['hidden']},
    ]}
    results = run(inventory, [EndpointResult('https://site.test/fetch?url=x')])
    assert {'csrf', 'ssrf', 'file_upload', 'business_logic'} <= {r['category'] for r in results}
    assert all(r['status'] == 'manual_review' and not r['tested'] for r in results)
    protected = next(r for r in results if r['category'] == 'csrf' and r['url'].endswith('/protected'))
    assert 'test edilmedi' in protected['reason']


def test_parameter_candidates_reject_other_hosts():
    eps = [EndpointResult('https://evil.test/?q=1'), EndpointResult('https://site.test/search?q=1')]
    result = _candidate_param_urls(eps, 'https://site.test')
    assert ('https://site.test/search?q=1', 'q') in result
    assert not any(url.startswith('https://evil.test') for url, _ in result)


def test_parameter_sqli_requires_new_error_vs_baseline():
    class Client:
        def get(self, url, follow_redirects=False):
            return httpx.Response(200, headers={'content-type': 'text/html'}, text='You have an error in your SQL syntax', request=httpx.Request('GET', url))
    ctx = SimpleNamespace(expired=lambda: False)
    findings = []
    _parameter_checks(Client(), 'site.test', 'https://site.test',
                      [EndpointResult('https://site.test/item?id=1')], findings, 6, ctx)
    assert not any('SQL' in item.name for item in findings)


def test_parameter_sqli_new_error_is_unverified():
    class Client:
        def get(self, url, follow_redirects=False):
            body = 'You have an error in your SQL syntax' if '%27' in url else 'OK'
            return httpx.Response(200, headers={'content-type': 'text/html'}, text=body, request=httpx.Request('GET', url))
    findings = []
    _parameter_checks(Client(), 'site.test', 'https://site.test',
                      [EndpointResult('https://site.test/item?id=1')], findings, 6,
                      SimpleNamespace(expired=lambda: False))
    assert findings
    assert all(f.raw['verification'] == 'unverified' for f in findings)
    assert all('Manual Review' in f.name for f in findings)


def test_local_ai_does_not_claim_automatic_confirmation():
    from app.ai.triage import local_analysis
    result = local_analysis({'id': 1, 'title': 'Potential SQL Injection', 'severity': 'medium', 'tags': [], 'verification': 'unverified'})
    assert 'doğrulandı' not in result.reason.lower()
    assert 'doğrulanmalıdır' in result.reason.lower()


def test_html_parser_detects_unnamed_file_field():
    from app.scanners.client_inventory import _HTML
    parser = _HTML()
    parser.feed('<form method="post"><input type="file"></form>')
    reviews = run({'forms': [dict(parser.forms[0], page='https://site.test/upload')]}, [])
    assert any(item['category'] == 'file_upload' for item in reviews)
