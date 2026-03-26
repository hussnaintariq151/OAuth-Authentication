# apps/authentication/utils/oauth_helpers.py
# ============================================================
#  Reusable helpers — Authorization Code Flow ke liye
#  Good & Bad practices clearly marked
# ============================================================

import secrets
import hashlib
import base64
from datetime import timedelta
from django.utils import timezone
from django.conf import settings


# ============================================================
# STATE PARAMETER — CSRF Prevention (Topic 07)
# ============================================================

def generate_state():
    """
    GOOD: cryptographically random state generate karo
    secrets module use karo — random module NAHI

    BAD:
        import random
        state = str(random.randint(1000, 9999))  # predictable!

    GOOD:
        state = secrets.token_urlsafe(32)  # 256-bit entropy
    """
    return secrets.token_urlsafe(32)


def store_state_in_session(request, state, extra_data=None):
    """
    GOOD: State server-side session mein store karo

    BAD:
        # localStorage mein store karna — JS se readable
        # Cookie mein without httpOnly — XSS se steal ho sakta
        # URL parameter mein store karna — logs mein ja sakta

    GOOD: Django session = server-side = safe
    extra_data mein returnTo URL store kar sakte ho (Topic 07)
    """
    request.session['oauth_state'] = {
        'value': state,
        'created_at': timezone.now().isoformat(),
        'extra': extra_data or {}
    }
    request.session.modified = True


def verify_state(request, received_state):
    """
    GOOD PRACTICE:
    1. State exist karta hai?
    2. Values match karti hain?
    3. Expired toh nahi?
    4. Use ke baad delete karo (one-time)

    BAD:
        if request.GET.get('state'):  # sirf presence check — value verify nahi!
            pass
    """
    stored = request.session.get('oauth_state')

    if not stored:
        return False, "No state in session — possible CSRF attack"

    # GOOD: Constant-time comparison — timing attack se bachao
    # BAD: if stored['value'] == received_state  (timing side-channel)
    if not secrets.compare_digest(stored['value'], received_state):
        return False, "State mismatch — CSRF attack detected"

    # GOOD: Expiry check
    from datetime import datetime
    created = datetime.fromisoformat(stored['created_at'])
    expiry_seconds = settings.OAUTH.get('STATE_EXPIRY', 600)
    if timezone.now().timestamp() - created.timestamp() > expiry_seconds:
        del request.session['oauth_state']
        return False, "State expired — please restart login"

    # GOOD: One-time use — delete after verification
    extra = stored.get('extra', {})
    del request.session['oauth_state']
    request.session.modified = True

    return True, extra


# ============================================================
# AUTHORIZATION CODE
# ============================================================

def generate_auth_code():
    """
    GOOD: Cryptographically random, URL-safe, enough entropy

    BAD:
        code = str(uuid.uuid4())          # UUID v4 is fine but shorter entropy
        code = hashlib.md5(str(time.time()))  # predictable!
        code = ''.join(random.choices(...))   # random, not secrets!
    """
    return secrets.token_urlsafe(48)  # 384-bit — overkill is good here


def create_authorization_code(client, user, redirect_uri, scopes,
                               code_challenge='', code_challenge_method=''):
    """
    GOOD PRACTICE:
    - Expiry explicitly set karo
    - Client aur redirect_uri bind karo
    - PKCE challenge store karo (Topic 02 mein use hoga)
    """
    from apps.authentication.models import AuthorizationCode

    expiry_seconds = settings.OAUTH.get('AUTH_CODE_EXPIRY', 600)

    # GOOD: Har call mein fresh code — reuse kabhi nahi
    code = generate_auth_code()

    auth_code = AuthorizationCode.objects.create(
        code=code,
        client=client,
        user=user,
        redirect_uri=redirect_uri,
        scopes=scopes,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=timezone.now() + timedelta(seconds=expiry_seconds),
    )

    return auth_code


# ============================================================
# TOKEN GENERATION
# ============================================================

def generate_access_token_value():
    """
    Abhi opaque token — Topic 10 mein JWT se replace karein ge.

    GOOD: secrets.token_urlsafe — URL safe, random
    BAD: uuid.uuid4() — weaker entropy for tokens
    """
    return secrets.token_urlsafe(64)  # 512-bit — future-proof


def create_access_token(client, user, scopes):
    """
    GOOD PRACTICE:
    - Short expiry (1 hour)
    - Scopes token ke saath stored
    - User null ho sakta hai (Client Credentials — Topic 03)
    """
    from apps.authentication.models import AccessToken

    expiry_seconds = settings.OAUTH.get('ACCESS_TOKEN_EXPIRY', 3600)
    token_value = generate_access_token_value()

    token = AccessToken.objects.create(
        token=token_value,
        client=client,
        user=user,
        scopes=scopes,
        expires_at=timezone.now() + timedelta(seconds=expiry_seconds),
    )
    return token


def create_refresh_token(client, user, access_token, scopes):
    """
    GOOD: Refresh token sirf offline_access scope hone pe issue karo
    BAD: Har request pe refresh token issue karna — unnecessary risk

    Note: Topic 12 mein rotation + reuse detection add hogi
    """
    from apps.authentication.models import RefreshToken

    # GOOD: offline_access scope check
    if 'offline_access' not in scopes:
        return None

    expiry_seconds = settings.OAUTH.get('REFRESH_TOKEN_EXPIRY', 2592000)
    token_value = secrets.token_urlsafe(64)

    refresh = RefreshToken.objects.create(
        token=token_value,
        access_token=access_token,
        client=client,
        user=user,
        scopes=scopes,
        expires_at=timezone.now() + timedelta(seconds=expiry_seconds),
    )
    return refresh


# ============================================================
# SCOPE VALIDATION
# ============================================================

def validate_scopes(requested_scopes, client_allowed_scopes):
    """
    GOOD: Server pe scope validate karo — client pe trust nahi

    BAD:
        return requested_scopes  # jo client maange de do — NEVER

    GOOD:
        Intersection: sirf woh scopes jo:
        1. Server ke supported scopes mein hain
        2. Client ko allowed hain
    """
    supported = set(settings.OAUTH.get('SUPPORTED_SCOPES', []))
    client_allowed = set(client_allowed_scopes)
    requested = set(requested_scopes)

    # GOOD: Triple check — supported AND client_allowed AND requested
    valid_scopes = requested & client_allowed & supported

    return list(valid_scopes)


# ============================================================
# REDIRECT URI VALIDATION
# ============================================================

def validate_redirect_uri(client, redirect_uri):
    """
    GOOD PRACTICE — Exact match only

    BAD examples that look safe but aren't:
        # 1. Prefix match:
        if redirect_uri.startswith(registered):  # evil.com/?redirect=yourapp.com
        
        # 2. Contains check:
        if registered in redirect_uri  # yourapp.com.evil.com
        
        # 3. No validation at all:
        return True  # token leak guaranteed

    GOOD: Exact string match
    """
    if not redirect_uri:
        return False, "redirect_uri is required"

    if not client.is_redirect_uri_valid(redirect_uri):
        return False, f"redirect_uri not registered for this client"

    # GOOD: HTTPS enforce karo production mein
    # BAD: HTTP allow karna — token URL mein travel karta hai
    from django.conf import settings as django_settings
    if not django_settings.DEBUG and not redirect_uri.startswith('https://'):
        return False, "redirect_uri must use HTTPS in production"

    return True, None


# ============================================================
# PKCE IMPORT — Topic 02
# ============================================================
# oauth_helpers.py mein direct import rakho taake views ko
# sirf ek jagah se import karna pade
from apps.authentication.utils.pkce import (
    validate_pkce_in_auth_request,
    verify_pkce,
    generate_pkce_pair,        # testing/docs ke liye
)