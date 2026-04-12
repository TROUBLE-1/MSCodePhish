"""Database models for device code phishing toolkit."""
from datetime import datetime
from app import db


class SMTPConfig(db.Model):
    """SMTP server configuration for sending phishing emails."""
    __tablename__ = "smtp_config"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, default="default")
    host = db.Column(db.String(256), nullable=False)
    port = db.Column(db.Integer, nullable=False, default=587)
    use_tls = db.Column(db.Boolean, default=True)
    username = db.Column(db.String(256))
    password = db.Column(db.String(512))  # Consider encrypting in production
    from_email = db.Column(db.String(256), nullable=False)
    from_name = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "use_tls": self.use_tls,
            "username": self.username,
            "from_email": self.from_email,
            "from_name": self.from_name,
            "is_active": self.is_active,
        }


class AzureAppConfig(db.Model):
    """Azure AD app registration (service principal) for device code flow."""
    __tablename__ = "azure_app_config"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, default="default")
    client_id = db.Column(db.String(256), nullable=False)
    client_secret = db.Column(db.String(512))  # Optional for public client
    tenant_id = db.Column(db.String(256), nullable=False)  # "common" for multi-tenant
    scope = db.Column(db.String(512), default="openid profile email User.Read offline_access")
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "client_id": self.client_id,
            "tenant_id": self.tenant_id,
            "scope": self.scope,
            "is_active": self.is_active,
        }


class Campaign(db.Model):
    """Phishing campaign: batch of device codes + emails."""
    __tablename__ = "campaigns"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256))
    # Delivery: none | smtp | azure | api
    email_delivery_method = db.Column(db.String(32), default="none")  # none, smtp, azure, api
    smtp_config_id = db.Column(db.Integer, db.ForeignKey("smtp_config.id"), nullable=True)  # when method=smtp
    azure_email_config_id = db.Column(db.Integer, db.ForeignKey("azure_app_config.id"), nullable=True)  # when method=azure
    azure_email_from = db.Column(db.String(256), nullable=True)  # UPN or user id to send as (Graph)
    email_subject = db.Column(db.String(512))
    email_body_html = db.Column(db.Text)
    # Optional extra resource scopes requested at device-code sign-in (space-separated).
    # e.g. "https://management.azure.com/.default https://vault.azure.net/.default" so ARM/Key Vault tokens work later.
    extra_scopes = db.Column(db.String(1024), nullable=True)
    # Optional per-campaign API endpoint path for programmatic session creation.
    api_path = db.Column(db.String(128), nullable=True, unique=True)
    target_count = db.Column(db.Integer, nullable=False)  # e.g. 50
    status = db.Column(db.String(32), default="draft")  # draft, running, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Optional override for public client_id when not using AzureAppConfig.
    public_client_id = db.Column(db.String(256), nullable=True)

    smtp_config = db.relationship("SMTPConfig", backref="campaigns", foreign_keys=[smtp_config_id])
    azure_email_config = db.relationship("AzureAppConfig", foreign_keys=[azure_email_config_id])
    sessions = db.relationship("DeviceCodeSession", backref="campaign", lazy="dynamic", cascade="all, delete-orphan")


class DeviceCodeSession(db.Model):
    """Single device code session: one code sent to one target."""
    __tablename__ = "device_code_sessions"
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.id"), nullable=False)
    target_email = db.Column(db.String(256))
    # Optional IP address of the client that initiated this session (for API-created sessions).
    source_ip = db.Column(db.String(64))
    user_code = db.Column(db.String(32))  # Code shown to user (e.g. ABCD-1234)
    device_code = db.Column(db.String(512))  # Used for token endpoint polling
    verification_uri = db.Column(db.String(512))
    message = db.Column(db.String(512))  # Message to display to user
    expires_at = db.Column(db.DateTime)
    status = db.Column(db.String(32), default="pending")  # pending, authorized, expired, denied, error
    error_message = db.Column(db.String(1024), nullable=True)  # details when status=error
    email_sent = db.Column(db.Boolean, default=False)
    email_sent_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    captured_token = db.relationship("CapturedToken", backref="session", uselist=False, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "campaign_id": self.campaign_id,
            "target_email": self.target_email,
            "user_code": self.user_code,
            "verification_uri": self.verification_uri,
            "message": self.message,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status,
            "error_message": self.error_message,
            "email_sent": self.email_sent,
            "email_sent_at": self.email_sent_at.isoformat() if self.email_sent_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class CapturedToken(db.Model):
    """Refresh + access token captured after user completes device login."""
    __tablename__ = "captured_tokens"
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey("device_code_sessions.id"), nullable=False)
    refresh_token = db.Column(db.Text, nullable=False)
    access_token = db.Column(db.Text)  # Latest access token (optional cache)
    access_token_expires_at = db.Column(db.DateTime)
    scope = db.Column(db.String(512))
    user_id = db.Column(db.String(256))
    user_email = db.Column(db.String(256))
    user_display_name = db.Column(db.String(256))
    tenant_id = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "user_email": self.user_email,
            "user_display_name": self.user_display_name,
            "tenant_id": self.tenant_id,
            "scope": self.scope,
            "has_refresh_token": bool(self.refresh_token),
            "access_token_expires_at": self.access_token_expires_at.isoformat() if self.access_token_expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class NotificationConfig(db.Model):
    """Global notification settings for Slack and Discord."""
    __tablename__ = "notification_config"
    id = db.Column(db.Integer, primary_key=True)
    # Slack
    slack_enabled = db.Column(db.Boolean, default=False)
    slack_bot_token = db.Column(db.String(512))
    slack_channel = db.Column(db.String(256))
    # Discord
    discord_enabled = db.Column(db.Boolean, default=False)
    discord_bot_token = db.Column(db.String(512))
    discord_channel_id = db.Column(db.String(256))
    # Per-event toggles
    notify_on_session_created = db.Column(db.Boolean, default=True)
    notify_on_status_authorized = db.Column(db.Boolean, default=True)
    notify_on_status_expired = db.Column(db.Boolean, default=True)
    notify_on_status_declined = db.Column(db.Boolean, default=True)
    notify_on_status_error = db.Column(db.Boolean, default=True)
    notify_on_status_cancelled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "slack_enabled": self.slack_enabled,
            "slack_channel": self.slack_channel,
            "discord_enabled": self.discord_enabled,
            "discord_channel_id": self.discord_channel_id,
        }


class User(db.Model):
    """Administrative user for logging into the portal."""
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    must_change_password = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
