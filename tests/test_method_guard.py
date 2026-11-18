from security.method_guard import (
    effective_method,
    normalize_method,
    is_safe_override,
    requires_csrf,
    strip_proxy_header
)


def test_override():
    assert effective_method('POST', 'DELETE') == 'DELETE'

def test_get_override():
    assert effective_method('GET', 'DELETE') == 'GET'

def test_normalize():
    assert normalize_method(' delete ') == 'DELETE'

def test_safe():
    assert is_safe_override('DELETE') is True

def test_trace():
    assert is_safe_override('TRACE') is False

def test_connect():
    assert is_safe_override('CONNECT') is False

def test_empty():
    assert is_safe_override('') is False

def test_csrf():
    assert requires_csrf('DELETE') is True

def test_csrf_get():
    assert requires_csrf('GET') is False

def test_strip():
    assert 'X-HTTP-Method-Override' not in strip_proxy_header({'X-HTTP-Method-Override': 'DELETE'})

def test_keep():
    assert strip_proxy_header({'X-Trace': '1'}) == {'X-Trace': '1'}

def test_dup():
    assert effective_method('POST', ['DELETE', 'PUT']) == 'POST'

def test_lower():
    assert normalize_method('delete') == 'DELETE'

def test_put():
    assert is_safe_override('PUT') is True

def test_log():
    assert effective_method('POST', 'PATCH') == 'PATCH'
