"""Background scheduler to poll device code sessions for token capture."""
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import ObjectDeletedError


def poll_pending_sessions(app):
    """Poll all pending device code sessions and capture tokens when user completes auth."""
    with app.app_context():
        from app import db
        from app.models import DeviceCodeSession, CapturedToken
        from app.device_code import poll_for_tokens
        from app.notification_sender import send_session_notification

        pending = DeviceCodeSession.query.filter(
            DeviceCodeSession.status == "pending",
            DeviceCodeSession.expires_at > datetime.utcnow(),
        ).all()

        for session in pending:
            # Session might have been deleted between the initial query and now.
            try:
                campaign = session.campaign
            except ObjectDeletedError:
                db.session.rollback()
                continue
            from app.services import get_effective_device_code_config
            tenant_id, client_id = get_effective_device_code_config(campaign)

            success, data = poll_for_tokens(tenant_id, client_id, session.device_code)
            if success:
                old_status = session.status
                session.status = "authorized"

                # Reuse existing captured token if present instead of inserting duplicates.
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
                    # Update fields in-place
                    token.refresh_token = data.get("refresh_token", token.refresh_token)
                    token.access_token = data.get("access_token") or token.access_token
                    token.scope = data.get("scope") or token.scope

                expires_in = data.get("expires_in")
                if expires_in:
                    from datetime import timedelta
                    token.access_token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)

                # Decode id_token (preferred) or access_token to capture user + tenant info.
                try:
                    import base64
                    import json

                    raw_id_token = data.get("id_token") or ""
                    raw_access_token = data.get("access_token") or ""

                    def _decode_jwt(token_str: str):
                        parts = token_str.split(".")
                        if len(parts) < 2:
                            return {}
                        payload = parts[1]
                        padding = "=" * ((4 - len(payload) % 4) % 4)
                        payload += padding
                        return json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")))

                    claims = {}
                    if raw_id_token:
                        claims = _decode_jwt(raw_id_token)
                    if not claims and raw_access_token:
                        claims = _decode_jwt(raw_access_token)

                    if claims:
                        token.user_id = claims.get("oid") or claims.get("sub") or token.user_id
                        token.user_email = claims.get("email") or claims.get("preferred_username") or token.user_email
                        token.user_display_name = claims.get("name") or token.user_display_name
                        token.tenant_id = claims.get("tid") or claims.get("tenant_id") or token.tenant_id
                except Exception:
                    # If decoding fails, we still keep the raw tokens.
                    pass

                db.session.commit()
                send_session_notification(session, event="status_authorized", old_status=old_status)
            else:
                err = data.get("error")
                # Only update status if still pending (avoid overwriting "authorized" when
                # device_code is already consumed and a later poll returns bad_verification_code).
                # Session might have been deleted between query and now; handle that gracefully.
                try:
                    db.session.refresh(session)
                except (InvalidRequestError, ObjectDeletedError):
                    db.session.rollback()
                    continue

                if session.status != "pending":
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
                elif err == "bad_verification_code":
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
    )
    scheduler.start()
    return scheduler
