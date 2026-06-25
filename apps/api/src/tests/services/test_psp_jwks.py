import time
import pytest
import jwt as pyjwt  # PyJWT 2.13.0 — the LH backend's JWT library
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.services.auth import psp_jwks


def _make_token(claims, key="secret", alg="HS256"):
    return pyjwt.encode(claims, key, algorithm=alg)


# ---------------------------------------------------------------------------
# Real RS256 signature path. Every test above stubs _verify_signature, so the
# algorithms=["RS256"] / issuer-equality / audience-intersection / require-exp
# logic never actually runs. These exercise it end-to-end with a locally
# generated RSA keypair and a stubbed JWKS client (no network).
# ---------------------------------------------------------------------------


def _rsa_pem_pair():
    """Return (private_pem, public_pem) for signing/verifying RS256 tokens."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


class _FakeSigningKey:
    def __init__(self, key):
        self.key = key


def _stub_jwks(monkeypatch, public_pem):
    """Point _jwks_client at a client that hands back our public key (no HTTP)."""
    class _Client:
        def get_signing_key_from_jwt(self, _token):
            return _FakeSigningKey(public_pem)

    monkeypatch.setattr(psp_jwks, "_jwks_client", lambda _iss: _Client())


def test_verify_signature_accepts_valid_rs256_token(monkeypatch):
    private_pem, public_pem = _rsa_pem_pair()
    _stub_jwks(monkeypatch, public_pem)
    token = _make_token(
        {"iss": "https://trusted/", "aud": "api://default", "email": "u@og.com", "exp": time.time() + 60},
        key=private_pem,
        alg="RS256",
    )
    claims = psp_jwks._verify_signature(token, "https://trusted/", {"api://default"})
    assert claims["email"] == "u@og.com"


def test_verify_signature_rejects_wrong_issuer(monkeypatch):
    private_pem, public_pem = _rsa_pem_pair()
    _stub_jwks(monkeypatch, public_pem)
    token = _make_token(
        {"iss": "https://evil/", "email": "u@og.com", "exp": time.time() + 60},
        key=private_pem,
        alg="RS256",
    )
    with pytest.raises(psp_jwks.ShellTokenError):
        psp_jwks._verify_signature(token, "https://trusted/", set())


def test_verify_signature_rejects_bad_signature(monkeypatch):
    # Sign with one key, verify against a *different* public key.
    private_pem, _ = _rsa_pem_pair()
    _, other_public_pem = _rsa_pem_pair()
    _stub_jwks(monkeypatch, other_public_pem)
    token = _make_token(
        {"iss": "https://trusted/", "email": "u@og.com", "exp": time.time() + 60},
        key=private_pem,
        alg="RS256",
    )
    with pytest.raises(psp_jwks.ShellTokenError):
        psp_jwks._verify_signature(token, "https://trusted/", set())


def test_verify_signature_rejects_disallowed_audience(monkeypatch):
    # Exercises the audience-enforcement branch (previously zero coverage).
    private_pem, public_pem = _rsa_pem_pair()
    _stub_jwks(monkeypatch, public_pem)
    token = _make_token(
        {"iss": "https://trusted/", "aud": "api://other", "email": "u@og.com", "exp": time.time() + 60},
        key=private_pem,
        alg="RS256",
    )
    with pytest.raises(psp_jwks.ShellTokenError):
        psp_jwks._verify_signature(token, "https://trusted/", {"api://default"})


def test_verify_signature_accepts_audience_from_list(monkeypatch):
    # aud as a list; intersection with the allowlist is non-empty → accepted.
    private_pem, public_pem = _rsa_pem_pair()
    _stub_jwks(monkeypatch, public_pem)
    token = _make_token(
        {"iss": "https://trusted/", "aud": ["api://other", "api://default"],
         "email": "u@og.com", "exp": time.time() + 60},
        key=private_pem,
        alg="RS256",
    )
    claims = psp_jwks._verify_signature(token, "https://trusted/", {"api://default"})
    assert claims["email"] == "u@og.com"


def test_verify_signature_requires_exp(monkeypatch):
    # A shell token minted without an exp must be rejected, not accepted.
    private_pem, public_pem = _rsa_pem_pair()
    _stub_jwks(monkeypatch, public_pem)
    token = _make_token(
        {"iss": "https://trusted/", "aud": "api://default", "email": "u@og.com"},
        key=private_pem,
        alg="RS256",
    )
    with pytest.raises(psp_jwks.ShellTokenError):
        psp_jwks._verify_signature(token, "https://trusted/", {"api://default"})


def test_rejects_untrusted_issuer(monkeypatch):
    monkeypatch.setattr(psp_jwks, "_trusted_issuers", lambda: {"https://trusted/"})
    token = _make_token({"iss": "https://evil/", "email": "a@b.com", "exp": time.time() + 60})
    with pytest.raises(psp_jwks.ShellTokenError):
        psp_jwks.validate_shell_token(token)


def test_extracts_email_for_trusted_issuer(monkeypatch):
    monkeypatch.setattr(psp_jwks, "_trusted_issuers", lambda: {"https://trusted/"})
    monkeypatch.setattr(psp_jwks, "_trusted_audiences", lambda: {"api://default"})
    monkeypatch.setattr(
        psp_jwks,
        "_verify_signature",
        lambda token, iss, auds: {
            "iss": "https://trusted/",
            "aud": "api://default",
            "email": "user@opengov.com",
        },
    )
    token = _make_token({"iss": "https://trusted/"})
    assert psp_jwks.validate_shell_token(token) == "user@opengov.com"


def test_missing_email_raises_when_userinfo_has_none(monkeypatch):
    # No email in the verified claims AND the userinfo fallback yields nothing
    # → the token is rejected with the single clear "no email" error.
    monkeypatch.setattr(psp_jwks, "_trusted_issuers", lambda: {"https://trusted/"})
    monkeypatch.setattr(psp_jwks, "_trusted_audiences", lambda: {"api://default"})
    monkeypatch.setattr(
        psp_jwks, "_verify_signature",
        lambda token, iss, auds: {"iss": "https://trusted/", "aud": "api://default"},
    )
    monkeypatch.setattr(psp_jwks, "_fetch_userinfo_email", lambda iss, tok, sub: None)
    token = _make_token({"iss": "https://trusted/"})
    with pytest.raises(psp_jwks.ShellTokenError):
        psp_jwks.validate_shell_token(token)


def test_falls_back_to_userinfo_when_email_absent(monkeypatch):
    # Org-AS access token: verified claims carry `sub` but no `email`; the
    # userinfo fallback supplies it. (Mirrors the mbr-agents API fix.)
    monkeypatch.setattr(psp_jwks, "_trusted_issuers", lambda: {"https://trusted/"})
    monkeypatch.setattr(psp_jwks, "_trusted_audiences", lambda: set())
    monkeypatch.setattr(
        psp_jwks, "_verify_signature",
        lambda token, iss, auds: {"iss": "https://trusted/", "sub": "okta|123"},
    )
    captured = {}

    def fake_fetch(issuer, tok, expected_sub):
        captured["args"] = (issuer, expected_sub)
        return "fallback@opengov.com"

    monkeypatch.setattr(psp_jwks, "_fetch_userinfo_email", fake_fetch)
    token = _make_token({"iss": "https://trusted/"})
    assert psp_jwks.validate_shell_token(token) == "fallback@opengov.com"
    # The verified token's sub is forwarded for the OIDC sub-match check.
    assert captured["args"] == ("https://trusted/", "okta|123")


def test_email_claim_skips_userinfo_fallback(monkeypatch):
    # A token that already carries `email` must NOT trigger the userinfo round-trip.
    monkeypatch.setattr(psp_jwks, "_trusted_issuers", lambda: {"https://trusted/"})
    monkeypatch.setattr(psp_jwks, "_trusted_audiences", lambda: set())
    monkeypatch.setattr(
        psp_jwks, "_verify_signature",
        lambda token, iss, auds: {"email": "claim@opengov.com", "sub": "okta|123"},
    )

    def boom(*_a, **_k):
        raise AssertionError("userinfo fallback must not run when email is present")

    monkeypatch.setattr(psp_jwks, "_fetch_userinfo_email", boom)
    token = _make_token({"iss": "https://trusted/"})
    assert psp_jwks.validate_shell_token(token) == "claim@opengov.com"


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def test_fetch_userinfo_email_returns_email_on_sub_match(monkeypatch):
    monkeypatch.setattr(
        psp_jwks, "_discovery_doc",
        lambda iss: {"userinfo_endpoint": "https://trusted/oauth2/v1/userinfo"},
    )
    monkeypatch.setattr(
        psp_jwks.httpx, "get",
        lambda url, **kw: _FakeResp({"sub": "okta|123", "email": "u@opengov.com"}),
    )
    assert psp_jwks._fetch_userinfo_email("https://trusted/", "tok", "okta|123") == "u@opengov.com"


def test_fetch_userinfo_email_rejects_sub_mismatch(monkeypatch):
    monkeypatch.setattr(
        psp_jwks, "_discovery_doc",
        lambda iss: {"userinfo_endpoint": "https://trusted/oauth2/v1/userinfo"},
    )
    monkeypatch.setattr(
        psp_jwks.httpx, "get",
        lambda url, **kw: _FakeResp({"sub": "okta|someone-else", "email": "u@opengov.com"}),
    )
    assert psp_jwks._fetch_userinfo_email("https://trusted/", "tok", "okta|123") is None


def test_fetch_userinfo_email_none_when_endpoint_absent(monkeypatch):
    monkeypatch.setattr(psp_jwks, "_discovery_doc", lambda iss: {})
    assert psp_jwks._fetch_userinfo_email("https://trusted/", "tok", "okta|123") is None


def test_passes_raw_issuer_with_trailing_slash_to_verifier(monkeypatch):
    # Bug 1 regression: the issuer handed to the signature verifier must keep
    # the trailing slash exactly as it appears in the token's iss claim.
    monkeypatch.setattr(psp_jwks, "_trusted_issuers", lambda: {"https://trusted/"})
    monkeypatch.setattr(psp_jwks, "_trusted_audiences", lambda: set())
    captured = {}

    def fake_verify(token, issuer, auds):
        captured["issuer"] = issuer
        return {"email": "u@og.com"}

    monkeypatch.setattr(psp_jwks, "_verify_signature", fake_verify)
    token = _make_token({"iss": "https://trusted/"})
    assert psp_jwks.validate_shell_token(token) == "u@og.com"
    assert captured["issuer"] == "https://trusted/"


def test_jwks_resolution_failure_becomes_shell_token_error(monkeypatch):
    # Bug 2 regression: discovery/JWKS failures must surface as ShellTokenError,
    # never as an unhandled exception (500).
    def boom(_iss):
        raise RuntimeError("discovery unreachable")

    monkeypatch.setattr(psp_jwks, "_jwks_client", boom)
    with pytest.raises(psp_jwks.ShellTokenError):
        psp_jwks._verify_signature("anytoken", "https://trusted/", set())
