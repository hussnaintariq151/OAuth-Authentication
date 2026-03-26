# apps/authentication/utils/pkce.py
# ============================================================
#  Topic 02 — PKCE (Proof Key for Code Exchange)
#  RFC 7636 — "Pixy"
#
#  Yeh file client-side aur server-side dono logic cover karti hai.
#  Mobile/SPA ke liye client_secret store nahi ho sakta —
#  PKCE us problem ka solution hai.
# ============================================================

import re
import secrets
import hashlib
import base64


# ============================================================
# CONSTANTS
# ============================================================

# RFC 7636 Section 4.1 — verifier length bounds
VERIFIER_MIN_LENGTH = 43
VERIFIER_MAX_LENGTH = 128

# RFC 7636 allowed characters: [A-Z] [a-z] [0-9] - . _ ~
VERIFIER_PATTERN = re.compile(r'^[A-Za-z0-9\-._~]+$')

SUPPORTED_METHODS = ('S256',)
# NOTE: 'plain' method deliberately NOT in SUPPORTED_METHODS
# plain method is only allowed when S256 is not possible — which
# in 2024+ is never true. plain = attacker intercepts code_challenge
# aur use as verifier. S256 = SHA-256 hash, irreversible.


# ============================================================
# CLIENT-SIDE HELPERS
# (In real flow yeh frontend/mobile pe hota hai,
#  yahan testing aur documentation ke liye)
# ============================================================

def generate_code_verifier():
    """
    RFC 7636 Section 4.1 compliant code_verifier generate karo.

    GOOD:
        secrets.token_urlsafe(96) → 96 bytes → 128 char base64url string
        Length: 128 chars — maximum entropy

    BAD:
        secrets.token_urlsafe(16) → 22 chars — RFC minimum se kam
        random.choices(...)       → random module, not cryptographic
        uuid.uuid4()              → only 122 bits, not URL-safe format
        'fixed_verifier_string'   → NEVER hardcode — defeats the purpose

    Returns: URL-safe base64 string, 43-128 chars, RFC 7636 charset
    """
    # GOOD: 96 random bytes → 128 char base64url (maximum allowed)
    # secrets.token_urlsafe already produces [A-Za-z0-9_-] charset
    # RFC 7636 also allows . ~ — token_urlsafe nahi banata inhe,
    # lekin [A-Za-z0-9_-] subset bhi valid hai
    return secrets.token_urlsafe(96)


def generate_code_challenge(code_verifier, method='S256'):
    """
    code_verifier se code_challenge derive karo.

    S256 method (ALWAYS use this):
        code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))

    GOOD:
        method = 'S256' — SHA-256 hash, one-way, attacker useless
        Padding strip karo (=) — RFC 7636 Section 4.2

    BAD:
        method = 'plain'  → code_challenge == code_verifier
                            attacker intercepts challenge = has verifier
        hashlib.md5()     → collision attacks possible
        base64.b64encode() without urlsafe → + aur / chars break URLs
    """
    if method == 'S256':
        # GOOD: SHA-256 → base64url → strip padding
        digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
        return challenge

    # BAD: plain method — only for illustration, never use
    if method == 'plain':
        # plain = code_challenge is literally the verifier
        # An attacker who intercepts /authorize request gets the challenge
        # and can use it directly as verifier — zero protection
        raise ValueError(
            "plain method is not supported. Always use S256. "
            "RFC 9700 Section 2.1.1 strongly discourages plain."
        )

    raise ValueError(f"Unsupported method: {method}. Only S256 is allowed.")


def generate_pkce_pair():
    """
    Convenience: ek saath verifier + challenge generate karo.

    Usage (client side, e.g. SPA ya mobile):
        verifier, challenge = generate_pkce_pair()
        # challenge → authorization request mein bhejo
        # verifier  → securely store karo (memory, not localStorage)
        #             token exchange pe bhejo

    GOOD: Yeh function sirf ek session ke liye — har auth request pe
          fresh pair generate karo. Reuse NAHI.
    """
    verifier  = generate_code_verifier()
    challenge = generate_code_challenge(verifier, method='S256')
    return verifier, challenge


# ============================================================
# SERVER-SIDE VALIDATION
# ============================================================

def validate_code_verifier_format(code_verifier):
    """
    Token endpoint pe — verifier format check karo PEHLE hash verification.

    GOOD: Early rejection saves compute + gives clear error
    BAD:  Directly hash karo bina format check ke — invalid input se
          unexpected behavior possible

    Returns: (is_valid: bool, error_message: str | None)
    """
    if not code_verifier:
        return False, "code_verifier is required when PKCE was used"

    length = len(code_verifier)

    if length < VERIFIER_MIN_LENGTH:
        return False, (
            f"code_verifier too short: {length} chars. "
            f"Minimum is {VERIFIER_MIN_LENGTH} (RFC 7636 Section 4.1)"
        )

    if length > VERIFIER_MAX_LENGTH:
        return False, (
            f"code_verifier too long: {length} chars. "
            f"Maximum is {VERIFIER_MAX_LENGTH} (RFC 7636 Section 4.1)"
        )

    if not VERIFIER_PATTERN.match(code_verifier):
        return False, (
            "code_verifier contains invalid characters. "
            "Allowed: [A-Za-z0-9-._~] (RFC 7636 Section 4.1)"
        )

    return True, None


def verify_pkce(code_verifier, stored_challenge, stored_method):
    """
    Token exchange pe — verifier aur stored challenge match karte hain?

    GOOD Practice — 4 step check:
    1. Format validate karo
    2. Method check (S256 only)
    3. SHA-256 compute karo verifier se
    4. secrets.compare_digest() — timing-safe comparison

    BAD:
        computed == stored_challenge       → timing attack possible
        if not code_verifier: return True  → PKCE bypass!
        method == 'plain': verifier==challenge → no protection
    """

    # Step 1: Format check
    is_valid, error = validate_code_verifier_format(code_verifier)
    if not is_valid:
        return False, error

    # Step 2: Method check — ONLY S256
    # BAD: elif method == 'plain': return code_verifier == stored_challenge
    if stored_method not in SUPPORTED_METHODS:
        return False, (
            f"Unsupported code_challenge_method: '{stored_method}'. "
            f"Only S256 is supported."
        )

    # Step 3: Recompute challenge from verifier
    digest    = hashlib.sha256(code_verifier.encode('ascii')).digest()
    computed  = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

    # Step 4: GOOD — timing-safe comparison
    # BAD: if computed == stored_challenge:  → timing side-channel
    if not secrets.compare_digest(computed, stored_challenge):
        return False, "PKCE verification failed — code_verifier does not match challenge"

    return True, None


def validate_pkce_in_auth_request(code_challenge, code_challenge_method, require_pkce=True):
    """
    Authorization endpoint pe — incoming PKCE params validate karo.

    require_pkce=True  → PKCE missing hone pe reject (recommended)
    require_pkce=False → PKCE optional (legacy clients ke liye only)

    GOOD: require_pkce=True enforce karo naye apps mein
    BAD:  require_pkce=False globally — public clients unprotected

    Returns: (is_valid: bool, error: str | None, method: str)
    """

    # GOOD: PKCE required enforce karo
    if not code_challenge:
        if require_pkce:
            return False, "code_challenge is required (PKCE enforced)", ''
        # optional mode — PKCE nahi aaya, proceed without it
        return True, None, ''

    # Method default S256
    method = code_challenge_method or 'S256'

    # GOOD: plain method reject karo
    # BAD: 'plain' ko silently accept karna
    if method == 'plain':
        return False, (
            "code_challenge_method=plain is not supported. "
            "Use S256. plain method provides no security over no PKCE."
        ), ''

    if method not in SUPPORTED_METHODS:
        return False, (
            f"Unsupported code_challenge_method: '{method}'. "
            f"Supported: {', '.join(SUPPORTED_METHODS)}"
        ), ''

    # GOOD: Challenge format basic check
    # S256 challenge should be 43 chars (256 bits → base64url without padding)
    if len(code_challenge) != 43:
        return False, (
            f"Invalid code_challenge length: {len(code_challenge)}. "
            "S256 challenges are exactly 43 characters."
        ), ''

    # GOOD: Base64url charset check
    if not re.match(r'^[A-Za-z0-9\-_]+$', code_challenge):
        return False, (
            "code_challenge contains invalid characters. "
            "Expected base64url encoding (RFC 4648 Section 5)."
        ), ''

    return True, None, method