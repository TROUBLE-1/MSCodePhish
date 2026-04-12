"""SMTP and Microsoft Graph email sending for phishing campaigns."""
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


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
    body = (body_html or "").replace("{{user_code}}", user_code or "")
    body = body.replace("{{verification_uri}}", verification_uri or "")
    body = body.replace("{{message}}", message_display or "")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = (subject or "Sign in to your account").replace("{{user_code}}", user_code or "")
    msg["From"] = f"{from_name} <{smtp_config.from_email}>" if from_name else smtp_config.from_email
    msg["To"] = to_email
    msg.attach(MIMEText(body, "html"))

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
    body = (body_html or "").replace("{{user_code}}", user_code or "")
    body = body.replace("{{verification_uri}}", verification_uri or "")
    body = body.replace("{{message}}", message_display or "")
    subject = (subject or "Sign in to your account").replace("{{user_code}}", user_code or "")

    url = f"https://graph.microsoft.com/v1.0/users/{from_user_id_or_upn}/sendMail"
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body},
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
