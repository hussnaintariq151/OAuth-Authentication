# apps/authentication/migrations/0002_pkce_required.py
# ============================================================
#  Topic 02 — PKCE
#  OAuthClient mein pkce_required field add karo
#
#  Run: python manage.py migrate authentication
# ============================================================

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        # Topic 01 ka initial migration
        ('authentication', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='oauthclient',
            name='pkce_required',
            field=models.BooleanField(
                default=True,
                help_text=(
                    'Require PKCE for this client. '
                    'Must be True for public clients (SPA, mobile). '
                    'RFC 9700 recommends True for all clients.'
                ),
            ),
        ),
    ]