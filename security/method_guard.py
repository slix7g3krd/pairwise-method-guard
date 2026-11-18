"""Gateway guard for the ``X-HTTP-Method-Override`` header.

The override header lets a client rewrite the HTTP method seen by the
application.  Without strict handling it enables method-confusion attacks:
a GET carrying the header is authorized as a read but executed as a
DELETE, a TRACE value makes the server echo the request back, duplicated
headers smuggle a second value past the checks, and proxies forward the
internal header to upstream services.

Every routing, authorization and audit-logging decision in the gateway
must be based on :func:`effective_method` -- the single, already validated
source of truth -- so the route match and the authorization check can
never diverge (the authorization is re-evaluated against the *resolved*
method after the override is applied).
"""

# Methods the gateway is willing to route.  TRACE (request echo / XST) and
# CONNECT (tunnel establishment) are deliberately excluded, as are any
# unknown or empty tokens.
ALLOWED_METHODS = frozenset({
    'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS',
})

# Methods that never mutate state and therefore never need a CSRF token.
CSRF_EXEMPT_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})

OVERRIDE_HEADER = 'X-HTTP-Method-Override'


def normalize_method(value):
    """Normalize a method token: trim surrounding whitespace, upper-case it.

    Missing or non-string values normalize to ``''`` so callers can treat
    them as invalid without special-casing ``None``.
    """
    if not isinstance(value, str):
        return ''
    return value.strip().upper()


def is_safe_override(value):
    """Return ``True`` only for a whitelisted, non-dangerous override value.

    TRACE/CONNECT, empty strings and arbitrary unknown tokens are rejected
    (fail closed): the caller must then keep the request's original method.
    """
    return normalize_method(value) in ALLOWED_METHODS


def effective_method(original, override=None):
    """Resolve the final method used for routing, authorization and logs.

    Rules:

    * Only **POST** requests may carry an override.  A GET/HEAD/... request
      keeps its original method, so a read request can never be upgraded
      into a write by smuggling the header.
    * Repeated override headers (more than one value) are rejected outright:
      the request keeps its original method instead of silently taking the
      last value, which different layers used to resolve differently.
    * The value is normalized (whitespace stripped, upper-cased) and must
      pass the method whitelist -- TRACE, CONNECT, empty and unknown values
      fall back to the original method.
    * The returned method is the *final* method.  Routing, the re-run
      authorization check and the audit log all consume this one value, so
      they cannot disagree and the log records what was actually executed.
    """
    method = normalize_method(original)

    if method != 'POST' or override is None:
        return method

    # Repeated headers arrive as a list/tuple of values.  Anything other
    # than exactly one value is ambiguous, so ignore the header entirely.
    if isinstance(override, (list, tuple)):
        if len(override) != 1:
            return method
        override = override[0]
    elif not isinstance(override, str):
        return method

    target = normalize_method(override)
    if not is_safe_override(target):
        return method
    return target


def requires_csrf(method):
    """Whether the (effective) method requires a CSRF token.

    Must be called with the *resolved* method from
    :func:`effective_method`, so a POST overridden to PUT/PATCH/DELETE is
    still protected -- the check follows the final method, not the verb
    that appeared on the wire.
    """
    return normalize_method(method) not in CSRF_EXEMPT_METHODS


def strip_proxy_header(headers):
    """Return a copy of *headers* with the override header removed.

    The header is an internal gateway signal and must never be forwarded to
    upstream services.  Matching is case-insensitive because HTTP header
    names are case-insensitive, and the input mapping is never mutated.
    """
    if not isinstance(headers, dict):
        return headers
    lowered = OVERRIDE_HEADER.lower()
    return {
        key: value
        for key, value in headers.items()
        if not (isinstance(key, str) and key.lower() == lowered)
    }
