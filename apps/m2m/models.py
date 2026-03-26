from django.db import models

# Create your models here.

# apps/m2m/models.py
# ============================================================
#  Topic 03 — Client Credentials Flow
#  Machine-to-Machine (M2M) Authentication
#
#  Naya model: ServiceClient
#  Kyun alag model? OAuthClient user-facing hai (browser flows).
#  ServiceClient purely machine identity hai — koi user, koi
#  redirect_uri, koi consent page nahi.
#
#  Real-world: Order Service → Analytics Service raat 2 baje
#  Koi user involved nahi — service apni identity prove karti hai.
# ============================================================

import uuid
import secrets
from django.db import models
from django.utils import timezone


class ServiceClient(models.Model):
    """
    Machine-to-Machine client — services ke liye.

    GOOD PRACTICE:
    - OAuthClient se alag model — concerns separated
    - client_type field — 'service' only, user flows nahi
    - No redirect_uris — M2M mein browser nahi hota
    - No user FK — sub claim mein service ID hoti hai
    - rate_limit_per_minute — per-service throttling
    - allowed_services — sirf specific services call kar sake

    BAD:
    - OAuthClient mein hi M2M flag lagana — model bloat
    - Service ko user-level scopes dena — over-permission
    - No rate limiting — ek service sab resources consume kare
    """

    # GOOD: UUID PK — sequential ID se enumeration attack
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Client identity
    client_id     = models.CharField(max_length=100, unique=True)
    # Topic 10 mein: bcrypt hash. Abhi plain (development only)
    client_secret = models.CharField(max_length=255)

    name        = models.CharField(max_length=200)
    description = models.TextField(blank=True)

    # GOOD: Client type explicitly stored — future-proof
    # BAD:  Type runtime pe guess karna
    CLIENT_TYPE_SERVICE = 'service'
    CLIENT_TYPE_CHOICES = [('service', 'Backend Service')]
    client_type = models.CharField(
        max_length=20,
        choices=CLIENT_TYPE_CHOICES,
        default=CLIENT_TYPE_SERVICE,
    )

    # GOOD: Scopes per service — least privilege
    # BAD:  Sab scopes sab services ko
    allowed_scopes = models.JSONField(
        default=list,
        help_text="e.g. ['read:orders', 'write:analytics']"
    )

    # GOOD: Allowed target services — service-to-service call control
    # Service A sirf B aur C ko call kar sake, D ko nahi
    allowed_services = models.JSONField(
        default=list,
        help_text="Service names this client can call. Empty = no restriction."
    )

    # GOOD: Per-service rate limiting
    # BAD:  Global rate limit — ek noisy service baaki sab affect kare
    rate_limit_per_minute = models.IntegerField(
        default=60,
        help_text="Max token requests per minute. 0 = unlimited (not recommended)."
    )

    # GOOD: Token TTL per service — sensitive services ko shorter TTL
    token_ttl_seconds = models.IntegerField(
        default=3600,
        help_text="Access token lifetime. Sensitive services: 900 (15 min)."
    )

    is_active  = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Audit: last token issued
    last_token_issued_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        app_label = 'm2m'
        db_table  = 'm2m_service_clients'

    def __str__(self):
        return f"{self.name} ({self.client_id})"


class ServiceAccessToken(models.Model):
    """
    M2M Access Token — user-linked AccessToken se alag kyun?

    GOOD:
    - user field nahi — M2M mein user nahi hota
    - service FK — kaunsi service ka token hai
    - sub claim mein service ka client_id hoga (Topic 10 JWT mein)
    - No refresh token — service silently naya token le sakti hai

    BAD:
    - User AccessToken table mein M2M tokens bhi store karna —
      user tokens aur service tokens mix ho jaate hain
    - Refresh token issue karna M2M ke liye —
      unnecessary, service naya token le sakti hai
    """

    id      = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token   = models.CharField(max_length=2000, unique=True)
    service = models.ForeignKey(
        ServiceClient,
        on_delete=models.CASCADE,
        related_name='tokens'
    )

    scopes     = models.JSONField(default=list)
    expires_at = models.DateTimeField()
    revoked    = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    # Audit fields — M2M mein important
    issuer_ip  = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        app_label = 'm2m'
        db_table  = 'm2m_service_tokens'
        indexes   = [
            # GOOD: Token lookup fast hona chahiye — har API request pe
            models.Index(fields=['token'], name='m2m_token_idx'),
            models.Index(fields=['service', 'revoked'], name='m2m_service_revoked_idx'),
        ]

    def is_valid(self):
        return not self.revoked and timezone.now() < self.expires_at

    def __str__(self):
        return f"Token for {self.service.name}"


class TokenRequestLog(models.Model):
    """
    GOOD: M2M token requests log karo — audit trail zaroori hai
    BAD:  Logging skip karna — breach ke baad kuch pata nahi chalega

    Compliance: SOC2, HIPAA, ISO 27001 — audit logs mandatory
    (Topic 15 mein detail, yahan foundation)
    """

    service    = models.ForeignKey(ServiceClient, on_delete=models.CASCADE)
    requested_at = models.DateTimeField(auto_now_add=True)
    success    = models.BooleanField()
    failure_reason = models.CharField(max_length=200, blank=True)
    client_ip  = models.GenericIPAddressField(null=True, blank=True)
    scopes_requested = models.JSONField(default=list)
    scopes_granted   = models.JSONField(default=list)

    class Meta:
        app_label = 'm2m'
        db_table  = 'm2m_token_request_logs'
        # GOOD: Latest logs pehle — monitoring dashboards ke liye
        ordering  = ['-requested_at']