# apps/authentication/views.py
# ============================================================
#  Topic 01 + Topic 02 — Authorization Code Flow + PKCE
#
#  Topic 02 changes (marked with # [T02]):
#    - PKCE required enforce kiya (was optional warn)
#    - validate_pkce_in_auth_request() full validation
#    - verify_pkce() from pkce.py (proper errors, timing-safe)
#    - plain method blocked at auth request level
#    - Session mein PKCE params store → POST pe cross-check
# ============================================================

import logging
import secrets as sec_module
from urllib.parse import urlencode

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views import View
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.conf import settings

from apps.authentication.models import OAuthClient, AuthorizationCode, AccessToken, RefreshToken
from apps.authentication.utils.oauth_helpers import (
    generate_state, store_state_in_session, verify_state,
    create_authorization_code, create_access_token, create_refresh_token,
    validate_scopes, validate_redirect_uri,
)
from apps.authentication.utils.pkce import (
    validate_pkce_in_auth_request,
    verify_pkce,
)

logger = logging.getLogger(__name__)


# ── Error helpers ─────────────────────────────────────────────────

def oauth_error_response(redirect_uri, error, error_description, state=None):
    """
    GOOD: urlencode use karo — manual f-string concat se special chars break hote hain
    BAD:  f"{redirect_uri}?error={error}&..." — spaces/ampersands break
    Exception: redirect_uri invalid ho → page error, NEVER redirect
    """
    params = {'error': error, 'error_description': error_description}
    if state:
        params['state'] = state
    return redirect(f"{redirect_uri}?{urlencode(params)}")


def oauth_error_page(request, error_description):
    return render(request, 'authentication/error.html', {'error': error_description})


# ── Authorization Endpoint ────────────────────────────────────────

@method_decorator(login_required, name='dispatch')
class AuthorizationView(View):

    def get(self, request):
        """
        Validation order — yeh sequence change mat karna:
        1. client_id      → page error if invalid
        2. redirect_uri   → page error if invalid  (open redirect prevention)
        3. response_type  → redirect error
        4. state          → redirect error
        5. PKCE [T02]     → redirect error (now enforced, not just warned)
        6. scopes         → redirect error
        7. Store state    → show consent page
        """
        client_id     = request.GET.get('client_id')
        redirect_uri  = request.GET.get('redirect_uri')
        response_type = request.GET.get('response_type')
        scope         = request.GET.get('scope', '')
        state         = request.GET.get('state')

        # 1. client_id
        try:
            client = OAuthClient.objects.get(client_id=client_id, is_active=True)
        except OAuthClient.DoesNotExist:
            logger.warning(f"Invalid client_id: {client_id}")
            return oauth_error_page(request, "Invalid client_id")

        # 2. redirect_uri — invalid → page error (not redirect)
        is_valid, error_msg = validate_redirect_uri(client, redirect_uri)
        if not is_valid:
            logger.warning(f"Invalid redirect_uri '{redirect_uri}' for client {client_id}")
            return oauth_error_page(request, error_msg)

        # 3. response_type — only 'code'
        if response_type != 'code':
            return oauth_error_response(
                redirect_uri, 'unsupported_response_type',
                'Only response_type=code supported. '
                'Implicit Flow (response_type=token) deprecated — RFC 9700.',
                state
            )

        # 4. State — required
        if not state:
            return oauth_error_response(
                redirect_uri, 'invalid_request', 'state parameter is required', None
            )

        # 5. [T02] PKCE — fully enforced
        code_challenge        = request.GET.get('code_challenge', '')
        code_challenge_method = request.GET.get('code_challenge_method', 'S256')

        # [T02] Per-client PKCE requirement
        # GOOD: Public clients (SPA/mobile) always require PKCE
        # BAD:  pkce_required = False globally
        require_pkce = getattr(client, 'pkce_required', True)

        pkce_valid, pkce_error, validated_method = validate_pkce_in_auth_request(
            code_challenge, code_challenge_method, require_pkce=require_pkce,
        )
        if not pkce_valid:
            # [T02] GOOD: Reject — zero tolerance
            # [T02] BAD (old): logger.info("consider using PKCE") then proceed
            logger.warning(f"PKCE validation failed — client={client_id}: {pkce_error}")
            return oauth_error_response(redirect_uri, 'invalid_request', pkce_error, state)

        # [T02] Use validated method (always 'S256' or '')
        effective_method = validated_method or 'S256'

        # 6. Scopes
        requested_scopes = scope.split() if scope else []
        valid_scopes = validate_scopes(requested_scopes, client.allowed_scopes)
        if not valid_scopes and requested_scopes:
            return oauth_error_response(
                redirect_uri, 'invalid_scope',
                'None of the requested scopes are valid for this client', state
            )

        # 7. Store state (with PKCE params) → show page
        # [T02] GOOD: Store PKCE in session too — POST pe tamper check
        # [T02] BAD:  Only store in hidden form fields — client can modify
        store_state_in_session(request, state, extra_data={
            'returnTo':              request.GET.get('returnTo', '/'),
            'code_challenge':        code_challenge,
            'code_challenge_method': effective_method,
        })

        return render(request, 'authentication/consent.html', {
            'client':                client,
            'scopes':                valid_scopes,
            'redirect_uri':          redirect_uri,
            'state':                 state,
            'response_type':         response_type,
            'code_challenge':        code_challenge,
            'code_challenge_method': effective_method,
        })

    def post(self, request):
        action        = request.POST.get('action')
        client_id     = request.POST.get('client_id')
        redirect_uri  = request.POST.get('redirect_uri')
        state         = request.POST.get('state')
        scopes        = request.POST.getlist('scopes')
        code_challenge        = request.POST.get('code_challenge', '')
        code_challenge_method = request.POST.get('code_challenge_method', 'S256')

        # State verify — POST pe bhi (not just GET)
        state_valid, extra = verify_state(request, state)
        if not state_valid:
            logger.error(f"State verification failed in POST: {extra}")
            return oauth_error_page(request, f"Security check failed: {extra}")

        # [T02] GOOD: Cross-check PKCE from session vs POST form data
        # Attacker can tamper hidden form fields — session is server-side
        session_challenge = extra.get('code_challenge', '')
        if session_challenge and session_challenge != code_challenge:
            logger.error(
                f"SECURITY: PKCE challenge tampered — client={client_id} "
                f"session={session_challenge[:10]}... post={code_challenge[:10]}..."
            )
            return oauth_error_page(request, "Security check failed: PKCE challenge mismatch")

        # Client re-validate
        try:
            client = OAuthClient.objects.get(client_id=client_id, is_active=True)
        except OAuthClient.DoesNotExist:
            return oauth_error_page(request, "Invalid client")

        # redirect_uri re-validate
        is_valid, error_msg = validate_redirect_uri(client, redirect_uri)
        if not is_valid:
            return oauth_error_page(request, error_msg)

        if action == 'deny':
            logger.info(f"User {request.user} denied consent for {client.name}")
            return oauth_error_response(redirect_uri, 'access_denied', 'User denied access', state)

        # Issue auth code — code NOT token (front-channel)
        auth_code = create_authorization_code(
            client=client,
            user=request.user,
            redirect_uri=redirect_uri,
            scopes=scopes,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

        logger.info(
            f"Auth code issued — user={request.user} client={client.name} "
            f"pkce={'yes' if code_challenge else 'no'}"
        )

        return redirect(f"{redirect_uri}?code={auth_code.code}&state={state}")


# ── Token Endpoint ────────────────────────────────────────────────

@csrf_exempt
@require_POST
def token_view(request):
    grant_type = request.POST.get('grant_type')
    if grant_type == 'authorization_code':
        return _handle_authorization_code_grant(request)
    elif grant_type == 'refresh_token':
        return _handle_refresh_token_grant(request)
    return JsonResponse({
        'error': 'unsupported_grant_type',
        'error_description': f'grant_type "{grant_type}" is not supported'
    }, status=400)


def _handle_authorization_code_grant(request):
    code_value    = request.POST.get('code')
    redirect_uri  = request.POST.get('redirect_uri')
    client_id     = request.POST.get('client_id')
    client_secret = request.POST.get('client_secret')

    if not all([code_value, redirect_uri, client_id, client_secret]):
        return JsonResponse({
            'error': 'invalid_request',
            'error_description': 'code, redirect_uri, client_id, client_secret — sab required'
        }, status=400)

    # Client authenticate
    try:
        client = OAuthClient.objects.get(client_id=client_id, is_active=True)
    except OAuthClient.DoesNotExist:
        logger.warning(f"Token request — invalid client_id: {client_id}")
        return JsonResponse({'error': 'invalid_client', 'error_description': 'Client authentication failed'}, status=401)

    # GOOD: Constant-time comparison — timing-safe
    # BAD:  client.client_secret == client_secret
    if not sec_module.compare_digest(client.client_secret, client_secret):
        logger.warning(f"Token request — wrong client_secret for: {client_id}")
        return JsonResponse({'error': 'invalid_client', 'error_description': 'Client authentication failed'}, status=401)

    # Auth code lookup
    try:
        auth_code = AuthorizationCode.objects.select_related('user', 'client').get(
            code=code_value, client=client,
        )
    except AuthorizationCode.DoesNotExist:
        logger.warning(f"Token request — invalid code for client {client_id}")
        return JsonResponse({'error': 'invalid_grant', 'error_description': 'Authorization code is invalid'}, status=400)

    if auth_code.is_expired():
        return JsonResponse({'error': 'invalid_grant', 'error_description': 'Authorization code expired'}, status=400)

    if auth_code.used:
        # GOOD: Code reuse = possible attack — log immediately
        logger.error(
            f"SECURITY: Auth code reuse — client={client_id} user={auth_code.user}. "
            f"Possible code injection attack!"
        )
        return JsonResponse({'error': 'invalid_grant', 'error_description': 'Code already used'}, status=400)

    if auth_code.redirect_uri != redirect_uri:
        logger.warning(f"redirect_uri mismatch — client {client_id}")
        return JsonResponse({'error': 'invalid_grant', 'error_description': 'redirect_uri mismatch'}, status=400)

    # [T02] PKCE verify — proper implementation
    if auth_code.code_challenge:
        code_verifier = request.POST.get('code_verifier', '')

        # [T02] GOOD: verify_pkce() from pkce.py
        #   - validates verifier format (length 43-128, charset)
        #   - rejects plain method
        #   - SHA-256 compute + secrets.compare_digest (timing-safe)
        #   - descriptive error messages
        #
        # [T02] BAD — old placeholder:
        #   if method == 'plain': return verifier == challenge
        #   if computed == stored_challenge:   ← timing attack
        pkce_ok, pkce_error = verify_pkce(
            code_verifier,
            auth_code.code_challenge,
            auth_code.code_challenge_method,
        )
        if not pkce_ok:
            logger.warning(f"PKCE verify failed — client={client_id}: {pkce_error}")
            return JsonResponse({
                'error': 'invalid_grant',
                'error_description': pkce_error or 'PKCE verification failed'
            }, status=400)

    elif getattr(client, 'pkce_required', True):
        # Defense-in-depth: code issued without challenge but client requires PKCE
        logger.error(f"SECURITY: PKCE required but no challenge stored — client={client_id}")
        return JsonResponse({'error': 'invalid_grant', 'error_description': 'PKCE required'}, status=400)

    # GOOD: Mark used=True BEFORE issuing token (race condition prevention)
    # BAD:  Issue token THEN mark used
    auth_code.used = True
    auth_code.save(update_fields=['used'])

    access_token  = create_access_token(client=client, user=auth_code.user, scopes=auth_code.scopes)
    refresh_token = create_refresh_token(client=client, user=auth_code.user, access_token=access_token, scopes=auth_code.scopes)

    logger.info(f"Tokens issued — user={auth_code.user} client={client.name}")

    response_data = {
        'access_token': access_token.token,
        'token_type':   'Bearer',
        'expires_in':   settings.OAUTH.get('ACCESS_TOKEN_EXPIRY', 3600),
        'scope':        ' '.join(access_token.scopes),
    }
    if refresh_token:
        response_data['refresh_token'] = refresh_token.token

    response = JsonResponse(response_data)
    response['Cache-Control'] = 'no-store'
    response['Pragma']        = 'no-cache'
    return response


def _handle_refresh_token_grant(request):
    refresh_token_value = request.POST.get('refresh_token')
    client_id           = request.POST.get('client_id')
    client_secret       = request.POST.get('client_secret')

    if not all([refresh_token_value, client_id, client_secret]):
        return JsonResponse({'error': 'invalid_request', 'error_description': 'refresh_token, client_id, client_secret required'}, status=400)

    try:
        client = OAuthClient.objects.get(client_id=client_id, is_active=True)
    except OAuthClient.DoesNotExist:
        return JsonResponse({'error': 'invalid_client'}, status=401)

    if not sec_module.compare_digest(client.client_secret, client_secret):
        return JsonResponse({'error': 'invalid_client'}, status=401)

    try:
        refresh_token = RefreshToken.objects.select_related('user', 'client').get(token=refresh_token_value, client=client)
    except RefreshToken.DoesNotExist:
        return JsonResponse({'error': 'invalid_grant', 'error_description': 'Invalid refresh token'}, status=400)

    if not refresh_token.is_valid():
        return JsonResponse({'error': 'invalid_grant', 'error_description': 'Refresh token expired or revoked'}, status=400)

    refresh_token.access_token.revoked = True
    refresh_token.access_token.save(update_fields=['revoked'])

    new_access_token = create_access_token(client=client, user=refresh_token.user, scopes=refresh_token.scopes)
    refresh_token.access_token = new_access_token
    refresh_token.save(update_fields=['access_token'])

    response = JsonResponse({
        'access_token': new_access_token.token,
        'token_type':   'Bearer',
        'expires_in':   settings.OAUTH.get('ACCESS_TOKEN_EXPIRY', 3600),
        'scope':        ' '.join(new_access_token.scopes),
    })
    response['Cache-Control'] = 'no-store'
    response['Pragma']        = 'no-cache'
    return response