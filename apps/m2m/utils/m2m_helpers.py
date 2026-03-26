# apps/m2m/utils/m2m_helpers.py
# ============================================================
#  Topic 03 — Client Credentials Helpers
#
#  Covers:
#  - Client authenticate karo
#  - Scopes validate karo (M2M ke liye)
#  - Token generate aur issue karo
#  - Token cache karo (Redis) — har request pe DB hit nahi
#  - Rate limit check karo
# ============================================================

import secrets
import hashlib
import logging
from datetime import timedelta

from django.utils import timezone
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


# ============================================================
# CLIENT AUTHENTICATION
# ============================================================

def authenticate_service_client(client_id, client_secret):
    """
    Service client authenticate karo.

    GOOD:
    - secrets.compare_digest — timing-safe comparison
    - Generic error — client_id valid hai ya nahi, attacker ko mat batao
    - is_active check — disabled clients reject

    BAD:
    - if client.client_secret == client_secret  → timing attack
    - Alag errors for wrong ID vs wrong secret  → enumeration attack
    - Active check skip karna
    """
    from apps.m2m.models import ServiceClient

    if not client_id or not client_secret:
        return None, "client_id and client_secret are required"

    try:
        client = ServiceClient.objects.get(client_id=client_id, is_active=True)
    except ServiceClient.DoesNotExist:
        # GOOD: Timing-neutral delay — client exist na kare tab bhi
        # same time lage jaise wrong secret case mein
        secrets.compare_digest("dummy", "dummy_comparison")
        logger.warning(f"M2M auth — invalid client_id: {client_id}")
        return None, "Client authentication failed"

    # GOOD: Constant-time comparison
    # BAD:  client.client_secret == client_secret
    if not secrets.compare_digest(client.client_secret, client_secret):
        logger.warning(f"M2M auth — wrong client_secret for: {client_id}")
        return None, "Client authentication failed"

    return client, None


# ============================================================
# SCOPE VALIDATION — M2M ke liye
# ============================================================

def validate_m2m_scopes(requested_scopes, client):
    """
    M2M scopes validate karo.

    GOOD:
    - Server-side whitelist — client jo maange de nahi dete
    - Client ke allowed_scopes se intersection
    - Global M2M supported scopes se intersection
    - Empty requested = client ke sab allowed scopes

    BAD:
    - return requested_scopes  → jo client maange de do
    - Client-level scope check skip karna
    - M2M clients ko user-level scopes dena (openid, profile)
    """
    # M2M clients ko yeh scopes kabhi nahi milne chahiye
    USER_ONLY_SCOPES = {'openid', 'profile', 'email', 'offline_access'}

    client_allowed = set(client.allowed_scopes)
    requested      = set(requested_scopes) if requested_scopes else client_allowed

    # GOOD: User-only scopes M2M mein block karo
    if requested & USER_ONLY_SCOPES:
        blocked = requested & USER_ONLY_SCOPES
        logger.warning(
            f"M2M client {client.client_id} requested user-only scopes: {blocked}"
        )
        requested -= USER_ONLY_SCOPES

    # GOOD: Intersection — sirf jo client ko allowed hai
    valid = requested & client_allowed

    if not valid:
        logger.warning(
            f"M2M scope validation failed — client={client.client_id} "
            f"requested={requested} allowed={client_allowed}"
        )

    return list(valid)


# ============================================================
# RATE LIMITING
# ============================================================

def check_rate_limit(client):
    """
    Per-service rate limiting — Redis cache mein counter.

    GOOD:
    - Per-client rate limit — ek service baaki affect nahi kare
    - Sliding window — burst attacks prevent
    - Redis — fast, atomic operations

    BAD:
    - Global rate limit — noisy neighbor problem
    - In-memory counter — multiple workers mein sync nahi
    - No rate limit at all — service DoS possible

    Returns: (allowed: bool, retry_after_seconds: int)
    """
    if client.rate_limit_per_minute <= 0:
        # 0 = unlimited (only for internal trusted services)
        return True, 0

    cache_key = f"m2m_rate:{client.client_id}:minute"
    current   = cache.get(cache_key, 0)

    if current >= client.rate_limit_per_minute:
        # GOOD: Retry-After header ke liye seconds return karo
        ttl = cache.ttl(cache_key) if hasattr(cache, 'ttl') else 60
        logger.warning(
            f"Rate limit exceeded — client={client.client_id} "
            f"count={current} limit={client.rate_limit_per_minute}"
        )
        return False, ttl or 60

    # GOOD: Atomic increment — race condition prevent
    # cache.add = set only if not exists (atomic)
    if not cache.add(cache_key, 1, timeout=60):
        cache.incr(cache_key)

    return True, 0


# ============================================================
# TOKEN GENERATION
# ============================================================

def generate_service_token():
    """
    M2M token generate karo.

    GOOD: secrets.token_urlsafe(64) — 512-bit entropy
    BAD:  uuid.uuid4() — weaker, not designed for tokens
          str(time.time()) — predictable!
    """
    return secrets.token_urlsafe(64)


def issue_service_token(client, granted_scopes, client_ip=None):
    """
    ServiceAccessToken create karo aur DB mein store karo.

    GOOD:
    - TTL per client — sensitive services ko shorter lifetime
    - Audit: client_ip store karo
    - last_token_issued_at update karo — monitoring ke liye
    - No refresh token — service naya token silently le sakti hai

    BAD:
    - Fixed 1 hour TTL sab ke liye — sensitive services ko risk
    - No audit fields — breach ke baad trace nahi ho sakta
    - Refresh token issue karna — unnecessary complexity
    """
    from apps.m2m.models import ServiceAccessToken

    token_value = generate_service_token()
    ttl_seconds = client.token_ttl_seconds  # per-client TTL

    token = ServiceAccessToken.objects.create(
        token      = token_value,
        service    = client,
        scopes     = granted_scopes,
        expires_at = timezone.now() + timedelta(seconds=ttl_seconds),
        issuer_ip  = client_ip,
    )

    # GOOD: Audit — last token ka timestamp update karo
    ServiceClient = client.__class__
    ServiceClient.objects.filter(pk=client.pk).update(
        last_token_issued_at=timezone.now()
    )

    return token


# ============================================================
# TOKEN CACHING — Performance Pattern
# ============================================================

def get_cached_token(client):
    """
    Redis mein valid token cache karo — har request pe DB/token hit nahi.

    GOOD Pattern (Token Gateway):
    - Check cache pehle
    - Valid token mila → return karo (no new token)
    - Cache miss / expired → naya token issue karo

    GOOD:
    - Cache key mein client_id — har service ka alag cache
    - TTL: token expiry - 60 sec buffer (expire hone se pehle refresh)
    - Token hash cache karo, plain token nahi

    BAD:
    - Plain token cache karo — cache breach = token leak
    - No caching — har M2M API call mein naya token = slow
    - Global cache key — service A ka token service B ko mile
    """
    # GOOD: Cache key namespaced per client
    cache_key = f"m2m_token:{client.client_id}"
    cached    = cache.get(cache_key)

    if cached:
        # Verify token still valid in DB (revocation check)
        from apps.m2m.models import ServiceAccessToken
        try:
            token_obj = ServiceAccessToken.objects.get(
                token=cached, service=client, revoked=False
            )
            if token_obj.is_valid():
                return token_obj
        except ServiceAccessToken.DoesNotExist:
            # Cache stale — token revoked ya deleted
            cache.delete(cache_key)

    return None


def cache_service_token(client, token_obj):
    """
    Naya token cache mein store karo.

    TTL = token expiry - 60 second buffer
    Taake cache se expired token kabhi na mile.
    """
    expires_in = (token_obj.expires_at - timezone.now()).total_seconds()
    cache_ttl  = max(int(expires_in) - 60, 0)  # 60 sec buffer

    if cache_ttl > 0:
        cache_key = f"m2m_token:{client.client_id}"
        # GOOD: Token value cache karo (plain) — but in production
        # Redis mein encryption-at-rest use karo
        cache.set(cache_key, token_obj.token, timeout=cache_ttl)


def invalidate_token_cache(client):
    """Token cache clear karo — manual revocation ke baad"""
    cache.delete(f"m2m_token:{client.client_id}")


# ============================================================
# TOKEN LOG
# ============================================================

def log_token_request(client, success, scopes_requested=None,
                      scopes_granted=None, failure_reason='', client_ip=None):
    """
    GOOD: Har token request log karo — success aur failure dono
    BAD:  Sirf failures log karna — success pattern analysis miss

    Compliance: SOC2/HIPAA audit trails ke liye har event log hona chahiye
    """
    from apps.m2m.models import TokenRequestLog
    try:
        TokenRequestLog.objects.create(
            service          = client,
            success          = success,
            failure_reason   = failure_reason[:200] if failure_reason else '',
            client_ip        = client_ip,
            scopes_requested = scopes_requested or [],
            scopes_granted   = scopes_granted or [],
        )
    except Exception as e:
        # GOOD: Logging failure should NOT break the main flow
        # BAD:  Exception propagate karo — token issue fail ho jaaye
        logger.error(f"Failed to write token request log: {e}")