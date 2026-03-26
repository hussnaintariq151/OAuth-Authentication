# apps/m2m/urls.py
# ============================================================
#  Topic 03 — M2M Endpoints
#
#  GOOD: /oauth/m2m/ prefix — user OAuth se clearly alag
#  BAD:  /oauth/token ek hi endpoint sab flows ke liye —
#        grant_type pe switch karo — confusion aur errors
# ============================================================

from django.urls import path
from apps.m2m import views

app_name = 'm2m'

urlpatterns = [
    # Client Credentials token issue
    path('oauth/m2m/token',  views.m2m_token_view,  name='m2m_token'),

    # Token revocation — RFC 7009
    path('oauth/m2m/revoke', views.m2m_revoke_view, name='m2m_revoke'),
]