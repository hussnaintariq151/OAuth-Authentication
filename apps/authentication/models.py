# apps/authentication/models.py
# ============================================================
#  Topic 01 — Authorization Code Flow
#  Models: OAuthClient, AuthorizationCode, AccessToken
# ============================================================

import uuid
import secrets
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings


# ============================================================
# OAuthClient — Registered applications
# ============================================================

class OAuthClient(models.Model):
    """
    GOOD PRACTICE:
    - client_id aur client_secret alag fields — ID public, secret private
    - client_secret hashed store karo (Topic 10 mein bcrypt add karein ge)
    - redirect_uris exact match ke liye stored — wildcard kabhi nahi
    """

    # GOOD: UUID as primary key — sequential IDs se enumeration attack possible hai
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # GOOD: client_id public facing, random enough to be unguessable
    client_id = models.CharField(max_length=100, unique=True)
    client_secret = models.CharField(max_length=255)  # Topic 10 mein hashed karein ge

    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)

    # GOOD: Newline-separated URIs — exact match enforce hoga
    redirect_uris = models.TextField(
        help_text="One redirect URI per line. Exact match required."
    )

    # GOOD: Grant types explicitly per client — least privilege
    allowed_grant_types = models.JSONField(
        default=list,
        help_text="e.g. ['authorization_code', 'refresh_token']"
    )

    # GOOD: Scopes per client — client sirf woh scopes use kar sakta jo usse mili hain
    allowed_scopes = models.JSONField(
        default=list,
        help_text="Scopes this client is allowed to request"
    )

    is_active = models.BooleanField(default=True)

    # [T02] PKCE requirement per client
    # GOOD: True for all new clients — public clients must always be True
    # BAD:  False globally — SPA/mobile clients have no protection
    pkce_required = models.BooleanField(
        default=True,
        help_text=(
            "Require PKCE for this client. "
            "Must be True for public clients (SPA, mobile). "
            "RFC 9700 recommends True for all clients."
        )
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'authentication'
        db_table = 'oauth_clients'

    def get_redirect_uris(self):
        """List of registered redirect URIs"""
        return [uri.strip() for uri in self.redirect_uris.splitlines() if uri.strip()]

    def is_redirect_uri_valid(self, uri):
        """
        GOOD: Exact string match — substring ya prefix match NAHI
        BAD example: uri.startswith(registered_uri)  ← attack possible
        """
        return uri in self.get_redirect_uris()

    def __str__(self):
        return f"{self.name} ({self.client_id})"


# ============================================================
# AuthorizationCode — Short-lived, one-time use
# ============================================================

class AuthorizationCode(models.Model):
    """
    GOOD PRACTICE:
    - Code short-lived hota hai (10 min max)
    - One-time use: used=True hone ke baad reject
    - PKCE support: code_challenge store karo (Topic 02 mein use hoga)
    - Client aur redirect_uri bind karo — token exchange pe verify
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # GOOD: secrets.token_urlsafe cryptographically random hai
    code = models.CharField(max_length=255, unique=True)

    client = models.ForeignKey(OAuthClient, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    # GOOD: redirect_uri code ke saath bind — exchange pe same URI aani chahiye
    redirect_uri = models.URLField()

    scopes = models.JSONField(default=list)

    # PKCE fields — Topic 02 mein full use hoga, yahan placeholder
    code_challenge = models.CharField(max_length=255, blank=True)
    code_challenge_method = models.CharField(
        max_length=10,
        blank=True,
        choices=[('S256', 'SHA-256'), ('plain', 'Plain')],
    )

    # GOOD: Expiry explicitly store karo — DB mein check karo
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)  # GOOD: one-time use flag

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'authentication'
        db_table = 'oauth_auth_codes'

    def is_expired(self):
        return timezone.now() > self.expires_at

    def is_valid(self):
        """GOOD: Dono check ek saath — expired ya used, dono se reject"""
        return not self.used and not self.is_expired()

    def __str__(self):
        return f"AuthCode for {self.user} / {self.client.name}"


# ============================================================
# AccessToken
# ============================================================

class AccessToken(models.Model):
    """
    GOOD PRACTICE:
    - Token value hashed store karo production mein
      (abhi plain — Topic 10 JWT mein properly karein ge)
    - Short expiry: 1 hour default
    - Scopes token ke saath bind — Resource Server validate karega
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token = models.CharField(max_length=2000, unique=True)  # JWT ya opaque

    client = models.ForeignKey(OAuthClient, on_delete=models.CASCADE)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, null=True, blank=True
        # null=True: Client Credentials mein user nahi hota (Topic 03)
    )

    scopes = models.JSONField(default=list)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'authentication'
        db_table = 'oauth_access_tokens'

    def is_valid(self):
        return not self.revoked and timezone.now() < self.expires_at

    def __str__(self):
        return f"Token for {self.user or 'service'} / {self.client.name}"


# ============================================================
# RefreshToken — Placeholder (Topic 12 mein full rotation)
# ============================================================

class RefreshToken(models.Model):
    """
    Topic 12 mein rotation aur reuse detection add hogi
    Abhi basic structure rakho
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token = models.CharField(max_length=255, unique=True)
    access_token = models.OneToOneField(
        AccessToken, on_delete=models.CASCADE, related_name='refresh_token'
    )
    client = models.ForeignKey(OAuthClient, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scopes = models.JSONField(default=list)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'authentication'
        db_table = 'oauth_refresh_tokens'

    def is_valid(self):
        return not self.revoked and timezone.now() < self.expires_at