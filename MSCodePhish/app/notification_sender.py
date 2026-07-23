"""Slack/Discord notifications for session events, driven by NotificationConfig."""
from typing import Optional, Tuple

import requests
from app.models import NotificationConfig, DeviceCodeSession

TEST_NOTIFICATION_MESSAGE = (
    "🧪 *Test notification from MSCodePhish*\n"
    "If you see this message, your integration is configured correctly."
)


def _build_message(session: DeviceCodeSession, event: str, old_status: Optional[str] = None) -> str:
    """Create a readable, emoji-friendly message for Slack/Discord."""
    campaign = session.campaign
    ct = session.captured_token
    target = session.display_target if hasattr(session, "display_target") else (
        session.target_email
        or (ct.user_email if ct else None)
        or (ct.user_display_name if ct else None)
        or (ct.user_id if ct else None)
        or "unknown target"
    )
    ip = session.source_ip or "unknown IP"

    if event == "session_created":
        title = "🆕 New device-code session created"
    elif event == "status_authorized":
        title = "✅ Session authorized"
    elif event == "status_expired":
        title = "⏰ Session expired"
    elif event == "status_declined":
        title = "🙅 Session declined by user"
    elif event == "status_error":
        title = "⚠️ Session error"
    elif event == "status_cancelled":
        title = "🛑 Session cancelled"
    else:
        title = f"🔔 Session update ({event})"

    lines = [
        title,
        f"📣 Campaign: *{campaign.name or 'Unnamed'}*",
        f"👤 Target: `{target}`",
        f"🆔 Session ID: `{session.id}`",
        f"🌐 IP: `{ip}`",
    ]

    if old_status is not None:
        lines.append(f"📊 Status: `{old_status}` → `{session.status}`")
    else:
        lines.append(f"📊 Status: `{session.status}`")

    if session.user_code:
        lines.append(f"🔑 User code: `{session.user_code}`")

    return "\n".join(lines)


def send_slack_message(bot_token: str, channel: str, message: str) -> Tuple[bool, str]:
    """Post a message to Slack. Returns (success, error_or_detail)."""
    token = (bot_token or "").strip()
    chan = (channel or "").strip()
    if not token:
        return False, "Slack bot token is required"
    if not chan:
        return False, "Slack channel is required"

    try:
        headers = {"Authorization": f"Bearer {token}"}
        payload = {"channel": chan, "text": message}
        resp = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers=headers,
            json=payload,
            timeout=10,
        )
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if resp.status_code >= 400 or not body.get("ok"):
            err = body.get("error") or body.get("warning") or resp.text or f"HTTP {resp.status_code}"
            return False, str(err)
        return True, "Slack message sent"
    except requests.RequestException as exc:
        return False, str(exc)


def send_discord_message(bot_token: str, channel_id: str, message: str) -> Tuple[bool, str]:
    """Post a message to Discord. Returns (success, error_or_detail)."""
    token = (bot_token or "").strip()
    channel = (channel_id or "").strip()
    if not token:
        return False, "Discord bot token is required"
    if not channel:
        return False, "Discord channel ID is required"

    try:
        url = f"https://discord.com/api/v10/channels/{channel}/messages"
        headers = {"Authorization": f"Bot {token}", "Content-Type": "application/json"}
        payload = {"content": message}
        resp = requests.post(url, headers=headers, json=payload, timeout=10)
        if resp.status_code >= 400:
            try:
                body = resp.json()
                err = body.get("message") or resp.text
            except ValueError:
                err = resp.text or f"HTTP {resp.status_code}"
            return False, str(err)
        return True, "Discord message sent"
    except requests.RequestException as exc:
        return False, str(exc)


def send_test_notification(platform: str, **credentials) -> Tuple[bool, str]:
    """Send a test notification to Slack or Discord using provided credentials."""
    platform_key = (platform or "").strip().lower()
    if platform_key == "slack":
        return send_slack_message(
            credentials.get("slack_bot_token"),
            credentials.get("slack_channel"),
            TEST_NOTIFICATION_MESSAGE,
        )
    if platform_key == "discord":
        return send_discord_message(
            credentials.get("discord_bot_token"),
            credentials.get("discord_channel_id"),
            TEST_NOTIFICATION_MESSAGE,
        )
    return False, "platform must be slack or discord"


def send_session_notification(session: DeviceCodeSession, event: str, old_status: Optional[str] = None) -> None:
    """Send a notification about a session event, if enabled in NotificationConfig."""
    try:
        cfg = NotificationConfig.query.first()
        if not cfg:
            return

        if event == "session_created" and not cfg.notify_on_session_created:
            return
        if event == "status_authorized" and not cfg.notify_on_status_authorized:
            return
        if event == "status_expired" and not cfg.notify_on_status_expired:
            return
        if event == "status_declined" and not cfg.notify_on_status_declined:
            return
        if event == "status_error" and not cfg.notify_on_status_error:
            return
        if event == "status_cancelled" and not cfg.notify_on_status_cancelled:
            return

        message = _build_message(session, event, old_status)

        if cfg.slack_enabled and cfg.slack_bot_token and cfg.slack_channel:
            send_slack_message(cfg.slack_bot_token, cfg.slack_channel, message)

        if cfg.discord_enabled and cfg.discord_bot_token and cfg.discord_channel_id:
            send_discord_message(cfg.discord_bot_token, cfg.discord_channel_id, message)
    except Exception:
        return
