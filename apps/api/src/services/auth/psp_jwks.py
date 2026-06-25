"""Provider-agnostic validation of shell-issued JWTs (Auth0 or Okta).

Validation is driven by the token's own `iss` claim — checked against an
allowlist — then OIDC discovery resolves the JWKS. No per-provider branching:
the shell's authProvider only changes which trusted issuer signs the token.
"""

import os
from functools import lru_cache

import httpx
import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWTError



class ShellTokenError(Exception):
    """Raised when a shell JWT is missing, untrusted, or invalid."""


def _trusted_issuers() -> set[str]:
    raw = os.getenv("PSP_TRUSTED_ISSUERS", "")
    return {i.strip().rstrip("/") + "/" for i in raw.split(",") if i.strip()}


def _trusted_audiences() -> set[str]:
    raw = os.getenv("PSP_TRUSTED_AUDIENCES", "")
    return {a.strip() for a in raw.split(",") if a.strip()}


@lru_cache(maxsize=8)
def _discovery_doc(issuer: str) -> dict:
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    resp = httpx.get(url, timeout=5.0)
    resp.raise_for_status()
    return resp.json()


def _discover_jwks_uri(issuer: str) -> str:
    return _discovery_doc(issuer)["jwks_uri"]


@lru_cache(maxsize=8)
def _jwks_client(issuer: str) -> PyJWKClient:
    # PyJWKClient fetches + caches the JWKS and selects the signing key by kid.
    return PyJWKClient(_discover_jwks_uri(issuer))


def _verify_signature(token: str, issuer: str, audiences: set[str]) -> dict:
    # `issuer` is the EXACT iss claim string from the token (trailing slash
    # preserved) so PyJWT's equality check matches Auth0 and Okta alike.
    try:
        signing_key = _jwks_client(issuer).get_signing_key_from_jwt(token)
    except Exception as err:  # discovery/network/kid failures → fail closed
        raise ShellTokenError(f"jwks resolution failed: {err}")

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=issuer,
            # require exp so a shell token minted without an expiry can never
            # validate (PyJWT only checks exp when the claim is present).
            options={"verify_aud": False, "require": ["exp"]},
        )
    except PyJWTError as err:
        raise ShellTokenError(f"signature/issuer check failed: {err}")

    if audiences:
        raw = claims.get("aud")
        token_auds = {raw} if isinstance(raw, str) else set(raw or [])
        if not (token_auds & audiences):
            raise ShellTokenError("audience not allowed")
    return claims


def _fetch_userinfo_email(issuer: str, token: str, expected_sub) -> str | None:
    """Resolve the user's email from the OIDC userinfo endpoint.

    Okta's ORG authorization server (issuer `https://<tenant>.okta.com`) issues
    access tokens with a fixed claim set that does NOT include `email`. When the
    verified access token omits it, we call the issuer's `userinfo_endpoint`
    with the same bearer (the shell requests the `email` scope, so userinfo
    returns it). A custom authorization server that embeds `email` in the access
    token never reaches this path.

    Returns the email, or `None` when the endpoint is unknown, unreachable, the
    userinfo `sub` does not match the verified token `sub` (OIDC Core §5.3.2), or
    no email is present. Failures resolve to `None` so the caller raises the
    single clear "no email" error rather than leaking transport details.
    """
    try:
        userinfo_uri = _discovery_doc(issuer).get("userinfo_endpoint")
    except Exception:
        return None
    if not userinfo_uri:
        return None
    try:
        resp = httpx.get(
            userinfo_uri,
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return None
    # OIDC Core §5.3.2: the userinfo `sub` MUST match the access token's `sub`,
    # else the email would belong to a different principal than the verified token.
    if expected_sub is not None and data.get("sub") != expected_sub:
        return None
    return data.get("email") or data.get("preferred_username") or None


def validate_shell_token(token: str) -> str:
    """Validate `token` and return the email claim, or raise ShellTokenError."""
    if not token:
        raise ShellTokenError("missing token")
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except PyJWTError as err:
        raise ShellTokenError(f"unparseable token: {err}")

    raw_iss = unverified.get("iss") or ""
    normalized = raw_iss.rstrip("/") + "/"
    if normalized not in _trusted_issuers():
        raise ShellTokenError(f"untrusted issuer: {normalized}")

    claims = _verify_signature(token, raw_iss, _trusted_audiences())
    email = claims.get("email") or claims.get("preferred_username")
    if not email:
        # Org-AS access tokens omit `email`; resolve it from userinfo instead of
        # rejecting the (otherwise valid) token.
        email = _fetch_userinfo_email(raw_iss, token, claims.get("sub"))
    if not email:
        raise ShellTokenError("no email claim in token")
    return email
