from django.shortcuts import render

# Create your views here.
# apps/m2m/views.py
# ============================================================
#  Topic 03 — Client Credentials Flow
#  Single endpoint: POST /oauth/m2m/token
#
#  Flow:
#  Service → client_id + client_secret → Access Token
#  No browser. No redirect. No user. No consent page.
# ============================================================

import logging

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils import timezone

from apps.m2m.utils.m2m_helpers import (
    authenticate_service_client,
    validate_m2m_scopes,
    check_rate_limit,
    get_cached_token,
    cache_service_token,
    issue_service_token,
    log_token_request,
)

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """
    GOOD: X-Forwarded-For header check karo (load balancer ke peeche)
    BAD:  REMOTE_ADDR only — proxy ke peeche wrong IP milega
    """
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded:
        # GOOD: First IP — original client (baaki proxies hain)
        return x_forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


@csrf_exempt
@require_POST
def m2m_token_view(request):
    """
    POST /oauth/m2m/token

    Client Credentials Grant — RFC 6749 Section 4.4

    Request:
        grant_type    = client_credentials  (required)
        client_id     = ...                 (required)
        client_secret = ...                 (required, POST body)
        scope         = ...                 (optional)

    Response:
        access_token, token_type, expires_in, scope

    GOOD:
    - No refresh_token in response — M2M mein nahi hota
    - sub claim = service client_id (user ID nahi)
    - Cache-Control: no-store
    - Token caching — performance
    - Rate limiting — abuse prevention
    - Audit logging — compliance

    BAD:
    - grant_type check skip karna
    - refresh_token issue karna M2M mein
    - client_secret URL mein — server logs mein jaata hai
    - No rate limiting
    - No audit log
    """
    grant_type = request.POST.get('grant_type')

    # ── Grant type check ──────────────────────────────────────
    # GOOD: Sirf client_credentials accept karo yahan
    # BAD:  authorization_code bhi accept karna — wrong endpoint
    if grant_type != 'client_credentials':
        return JsonResponse({
            'error': 'unsupported_grant_type',
            'error_description': (
                'This endpoint only supports grant_type=client_credentials. '
                'For user flows use /oauth/authorize.'
            )
        }, status=400)

    client_id     = request.POST.get('client_id')
    client_secret = request.POST.get('client_secret')
    scope_param   = request.POST.get('scope', '')
    client_ip     = get_client_ip(request)

    requested_scopes = scope_param.split() if scope_param else []

    # ── Client authenticate ───────────────────────────────────
    # GOOD: POST body mein client_secret
    # BAD:  GET /m2m/token?client_secret=... — server logs mein!
    client, auth_error = authenticate_service_client(client_id, client_secret)

    if not client:
        # Log failure
        log_token_request(
            client         = None,
            success        = False,
            scopes_requested = requested_scopes,
            failure_reason = auth_error,
            client_ip      = client_ip,
        ) if False else None  # client None hai, log skip karo
        logger.warning(f"M2M auth failed — ip={client_ip}: {auth_error}")

        return JsonResponse({
            'error': 'invalid_client',
            'error_description': 'Client authentication failed'
        }, status=401)

    # ── Rate limit check ──────────────────────────────────────
    # GOOD: Auth ke baad rate limit check karo
    # BAD:  Rate limit before auth — unauthenticated requests bhi count hoon
    allowed, retry_after = check_rate_limit(client)

    if not allowed:
        log_token_request(
            client           = client,
            success          = False,
            scopes_requested = requested_scopes,
            failure_reason   = 'rate_limit_exceeded',
            client_ip        = client_ip,
        )
        response = JsonResponse({
            'error': 'rate_limit_exceeded',
            'error_description': (
                f'Too many token requests. '
                f'Limit: {client.rate_limit_per_minute}/minute.'
            )
        }, status=429)
        # GOOD: Retry-After header — client ko batao kab retry kare
        response['Retry-After'] = str(retry_after)
        return response

    # ── Scope validation ──────────────────────────────────────
    granted_scopes = validate_m2m_scopes(requested_scopes, client)

    if requested_scopes and not granted_scopes:
        log_token_request(
            client           = client,
            success          = False,
            scopes_requested = requested_scopes,
            failure_reason   = 'invalid_scope',
            client_ip        = client_ip,
        )
        return JsonResponse({
            'error': 'invalid_scope',
            'error_description': (
                'None of the requested scopes are valid for this service client. '
                f'Allowed: {client.allowed_scopes}'
            )
        }, status=400)

    # Scope nahi diya → client ke sab allowed scopes grant karo
    if not granted_scopes:
        granted_scopes = list(client.allowed_scopes)

    # ── Token cache check ────────────────────────────────────
    # GOOD: Valid token already hai → reuse karo, naya mat banao
    # BAD:  Har request pe naya token — DB load + unnecessary rotation
    cached_token = get_cached_token(client)

    if cached_token:
        # GOOD: Cached token ka scope check — granted scopes cover ho?
        if set(granted_scopes).issubset(set(cached_token.scopes)):
            logger.debug(f"M2M cache hit — client={client.client_id}")

            expires_in = int(
                (cached_token.expires_at - timezone.now()).total_seconds()
            )
            response = JsonResponse({
                'access_token': cached_token.token,
                'token_type':   'Bearer',
                'expires_in':   expires_in,
                'scope':        ' '.join(cached_token.scopes),
                # GOOD: sub = service identity, not user ID
                'sub':          client.client_id,
            })
            response['Cache-Control'] = 'no-store'
            response['Pragma']        = 'no-cache'
            return response

    # ── Issue new token ───────────────────────────────────────
    token = issue_service_token(
        client         = client,
        granted_scopes = granted_scopes,
        client_ip      = client_ip,
    )

    # Cache karo future requests ke liye
    cache_service_token(client, token)

    # Audit log — success
    log_token_request(
        client           = client,
        success          = True,
        scopes_requested = requested_scopes,
        scopes_granted   = granted_scopes,
        client_ip        = client_ip,
    )

    logger.info(
        f"M2M token issued — service={client.name} "
        f"scopes={granted_scopes} ip={client_ip}"
    )

    expires_in = int(
        (token.expires_at - timezone.now()).total_seconds()
    )

    # ── Response ─────────────────────────────────────────────
    # GOOD: RFC 6749 compliant response
    # NOTE: No refresh_token — M2M mein nahi hota
    #       Service silently naya token le sakti hai
    response = JsonResponse({
        'access_token': token.token,
        'token_type':   'Bearer',
        'expires_in':   expires_in,
        'scope':        ' '.join(granted_scopes),
        # GOOD: sub = service client_id — user ID nahi
        # Topic 10 (JWT) mein yeh claim JWT payload mein hogi
        'sub':          client.client_id,
    })
    # GOOD: Token response cache na ho — proxy ya browser store na kare
    response['Cache-Control'] = 'no-store'
    response['Pragma']        = 'no-cache'
    return response


@csrf_exempt
@require_POST
def m2m_revoke_view(request):
    """
    POST /oauth/m2m/revoke

    Service token manually revoke karo.
    Use case: secret rotation, security incident, service decommission.

    GOOD: Revocation endpoint hona chahiye — RFC 7009
    BAD:  Sirf expiry pe rely karna — breach ke baad token kaise cancel karein?
    """
    from apps.m2m.models import ServiceAccessToken

    client_id     = request.POST.get('client_id')
    client_secret = request.POST.get('client_secret')
    token_value   = request.POST.get('token')

    client, auth_error = authenticate_service_client(client_id, client_secret)
    if not client:
        return JsonResponse({'error': 'invalid_client'}, status=401)

    if not token_value:
        return JsonResponse({
            'error': 'invalid_request',
            'error_description': 'token parameter is required'
        }, status=400)

    try:
        token = ServiceAccessToken.objects.get(token=token_value, service=client)
        token.revoked = True
        token.save(update_fields=['revoked'])

        # GOOD: Cache bhi invalidate karo
        invalidate_token_cache(client)

        logger.info(f"M2M token revoked — service={client.name}")
        # RFC 7009: Successful revocation = 200 OK, empty body
        return JsonResponse({}, status=200)

    except ServiceAccessToken.DoesNotExist:
        # GOOD: Token exist na kare tab bhi 200 return karo
        # RFC 7009 Section 2.2: "invalid tokens do not cause an error response"
        return JsonResponse({}, status=200)


def invalidate_token_cache(client):
    from django.core.cache import cache
    cache.delete(f"m2m_token:{client.client_id}")