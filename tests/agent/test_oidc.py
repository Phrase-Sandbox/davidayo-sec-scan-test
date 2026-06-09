"""GitHub OIDC verifier — covers happy path, every rejection branch, and JWKS cache behaviour.

All tests use an in-test RSA keypair so no network/keys/env is needed. The
JWKS fetch is injected via ``_JwksCache(fetcher=...)`` — production code uses
the default ``urlopen``-based fetcher.
"""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from security_scanner.agent.oidc import (
    GITHUB_OIDC_ISSUER,
    GitHubIdentity,
    OidcVerificationError,
    _JwksCache,
    looks_like_jwt,
    verify_github_oidc,
)

AUDIENCE = "phrase-scanner"
WORKFLOW_PREFIX = "Phrase-Sandbox/master-scanner-pipeline/.github/workflows/scanner.yml@"


# ---------- helpers --------------------------------------------------------


def _make_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


def _priv_pem(priv: rsa.RSAPrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _make_token(priv: rsa.RSAPrivateKey, kid: str, **claims) -> str:
    now = int(time.time())
    payload = {
        "iss": GITHUB_OIDC_ISSUER,
        "aud": AUDIENCE,
        "sub": "repo:Phrase-Sandbox/payments-api:ref:refs/heads/main",
        "iat": now - 5,
        "nbf": now - 5,
        "exp": now + 300,
        "repository": "Phrase-Sandbox/payments-api",
        "job_workflow_ref": f"{WORKFLOW_PREFIX}refs/tags/v2",
        "run_id": "999",
        "actor": "alice",
    }
    payload.update(claims)
    return jwt.encode(_priv_pem(priv), payload, algorithm="RS256", headers={"kid": kid})


# Stash for the simple "constant key" tests. PyJWT.encode actually wants the
# private key passed as the key arg — wrap it.
def _encode(priv: rsa.RSAPrivateKey, payload: dict, kid: str) -> str:
    return jwt.encode(payload, _priv_pem(priv), algorithm="RS256", headers={"kid": kid})


def _mint(priv: rsa.RSAPrivateKey, kid: str = "test-kid-1", **overrides) -> str:
    now = int(time.time())
    payload = {
        "iss": GITHUB_OIDC_ISSUER,
        "aud": AUDIENCE,
        "sub": "repo:Phrase-Sandbox/payments-api:ref:refs/heads/main",
        "iat": now - 5,
        "nbf": now - 5,
        "exp": now + 300,
        "repository": "Phrase-Sandbox/payments-api",
        "job_workflow_ref": f"{WORKFLOW_PREFIX}refs/tags/v2",
        "run_id": "999",
        "actor": "alice",
    }
    payload.update(overrides)
    return _encode(priv, payload, kid)


def _cache_with(public_key, kid: str = "test-kid-1") -> _JwksCache:
    return _JwksCache(fetcher=lambda: {kid: public_key})


# ---------- happy path -----------------------------------------------------


def test_valid_token_returns_identity():
    priv, pub = _make_keypair()
    token = _mint(priv)
    identity = verify_github_oidc(
        token,
        audience=AUDIENCE,
        allowed_workflow_refs=[WORKFLOW_PREFIX],
        cache=_cache_with(pub),
    )
    assert isinstance(identity, GitHubIdentity)
    assert identity.repository == "Phrase-Sandbox/payments-api"
    assert identity.actor == "alice"
    assert identity.run_id == "999"
    assert identity.workflow_ref.startswith(WORKFLOW_PREFIX)


# ---------- rejection branches ---------------------------------------------


def test_wrong_audience_rejected():
    priv, pub = _make_keypair()
    token = _mint(priv, aud="someone-else")
    with pytest.raises(OidcVerificationError):
        verify_github_oidc(
            token,
            audience=AUDIENCE,
            allowed_workflow_refs=[WORKFLOW_PREFIX],
            cache=_cache_with(pub),
        )


def test_wrong_issuer_rejected():
    priv, pub = _make_keypair()
    token = _mint(priv, iss="https://evil.example.com")
    with pytest.raises(OidcVerificationError):
        verify_github_oidc(
            token,
            audience=AUDIENCE,
            allowed_workflow_refs=[WORKFLOW_PREFIX],
            cache=_cache_with(pub),
        )


def test_expired_token_rejected():
    priv, pub = _make_keypair()
    now = int(time.time())
    token = _mint(priv, iat=now - 1000, nbf=now - 1000, exp=now - 100)
    with pytest.raises(OidcVerificationError):
        verify_github_oidc(
            token,
            audience=AUDIENCE,
            allowed_workflow_refs=[WORKFLOW_PREFIX],
            cache=_cache_with(pub),
        )


def test_workflow_ref_not_in_allowlist_rejected():
    priv, pub = _make_keypair()
    token = _mint(
        priv, job_workflow_ref="OtherOrg/some-other-repo/.github/workflows/x.yml@refs/heads/main"
    )
    with pytest.raises(OidcVerificationError, match="not in allowlist"):
        verify_github_oidc(
            token,
            audience=AUDIENCE,
            allowed_workflow_refs=[WORKFLOW_PREFIX],
            cache=_cache_with(pub),
        )


def test_bad_signature_rejected():
    priv_real, pub_real = _make_keypair()
    priv_attacker, _ = _make_keypair()
    # Signed by attacker; cache only knows the real key.
    token = _mint(priv_attacker)
    with pytest.raises(OidcVerificationError):
        verify_github_oidc(
            token,
            audience=AUDIENCE,
            allowed_workflow_refs=[WORKFLOW_PREFIX],
            cache=_cache_with(pub_real),
        )


def test_unknown_kid_rejected():
    priv, pub = _make_keypair()
    token = _mint(priv, kid="unknown-kid")
    with pytest.raises(OidcVerificationError, match="unknown signing key"):
        verify_github_oidc(
            token,
            audience=AUDIENCE,
            allowed_workflow_refs=[WORKFLOW_PREFIX],
            cache=_cache_with(pub, kid="real-kid"),
        )


def test_missing_repository_claim_rejected():
    priv, pub = _make_keypair()
    token = _mint(priv, repository="")
    with pytest.raises(OidcVerificationError, match="missing `repository`"):
        verify_github_oidc(
            token,
            audience=AUDIENCE,
            allowed_workflow_refs=[WORKFLOW_PREFIX],
            cache=_cache_with(pub),
        )


def test_malformed_token_rejected():
    _, pub = _make_keypair()
    with pytest.raises(OidcVerificationError, match="malformed"):
        verify_github_oidc(
            "not.a.jwt.really",
            audience=AUDIENCE,
            allowed_workflow_refs=[WORKFLOW_PREFIX],
            cache=_cache_with(pub),
        )


# ---------- JWKS cache behaviour -------------------------------------------


def test_jwks_cache_serves_repeat_calls_without_refetch():
    priv, pub = _make_keypair()
    calls = {"n": 0}

    def fetcher():
        calls["n"] += 1
        return {"test-kid-1": pub}

    cache = _JwksCache(fetcher=fetcher)
    token = _mint(priv)
    verify_github_oidc(
        token, audience=AUDIENCE, allowed_workflow_refs=[WORKFLOW_PREFIX], cache=cache
    )
    verify_github_oidc(
        token, audience=AUDIENCE, allowed_workflow_refs=[WORKFLOW_PREFIX], cache=cache
    )
    assert calls["n"] == 1


def test_jwks_cache_falls_back_to_last_known_when_refetch_fails(monkeypatch):
    priv, pub = _make_keypair()
    call_n = {"i": 0}

    def fetcher():
        call_n["i"] += 1
        if call_n["i"] == 1:
            return {"test-kid-1": pub}
        raise RuntimeError("github unreachable")

    cache = _JwksCache(fetcher=fetcher)
    token = _mint(priv)
    # Prime cache.
    verify_github_oidc(
        token, audience=AUDIENCE, allowed_workflow_refs=[WORKFLOW_PREFIX], cache=cache
    )

    # Force cache expiry; the next call should still succeed using stale keys.
    import security_scanner.agent.oidc as oidc_mod

    monkeypatch.setattr(oidc_mod, "_JWKS_TTL_SECONDS", -1)
    verify_github_oidc(
        token, audience=AUDIENCE, allowed_workflow_refs=[WORKFLOW_PREFIX], cache=cache
    )
    assert call_n["i"] == 2  # refetch was attempted; we tolerated its failure


def test_jwks_cache_raises_on_first_fetch_failure():
    def fetcher():
        raise RuntimeError("github down at boot")

    cache = _JwksCache(fetcher=fetcher)
    priv, _ = _make_keypair()
    token = _mint(priv)
    with pytest.raises(OidcVerificationError, match="unable to fetch JWKS"):
        verify_github_oidc(
            token, audience=AUDIENCE, allowed_workflow_refs=[WORKFLOW_PREFIX], cache=cache
        )


# ---------- looks_like_jwt heuristic ---------------------------------------


def test_looks_like_jwt_three_segments():
    assert looks_like_jwt("aaa.bbb.ccc") is True


def test_looks_like_jwt_rejects_bearer_tokens():
    assert looks_like_jwt("phs_local_tok-abc123def") is False
    assert looks_like_jwt("local-test-token") is False


def test_looks_like_jwt_rejects_empty_segments():
    assert looks_like_jwt("aaa..ccc") is False


# ---------- allowlist-disabled mode ----------------------------------------


def test_empty_allowlist_skips_workflow_ref_check():
    """When the allowlist is empty, any workflow_ref passes. Tests should
    NEVER use this — it's only for ops emergencies where you need to disable
    the allowlist temporarily."""
    priv, pub = _make_keypair()
    token = _mint(
        priv, job_workflow_ref="Anyone/anything/.github/workflows/foo.yml@refs/heads/main"
    )
    identity = verify_github_oidc(
        token,
        audience=AUDIENCE,
        allowed_workflow_refs=[],
        cache=_cache_with(pub),
    )
    assert identity.repository == "Phrase-Sandbox/payments-api"
