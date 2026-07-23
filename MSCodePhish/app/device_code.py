"""Microsoft Device Code OAuth 2.0 flow (device authorization grant).

Per Microsoft docs (https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code):
- Device code request: POST /devicecode with client_id and scope only (no client_secret).
- Token request: POST /token with grant_type, client_id, device_code (no client_secret for public clients).
So like 'az login --use-device-code', you can use a public client with no app registration.
"""
import requests


DEVICE_AUTH_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
TOKEN_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
FULL_SCOPE = "https://management.core.windows.net//.default offline_access openid profile email"
CLAIMS_CP1 = '{"access_token":{"xms_cc":{"values":["CP1"]}}}'
# Default refresh scope when caller does not pass one (Graph + OIDC).
DEFAULT_REFRESH_SCOPE = (
    "https://graph.microsoft.com/.default offline_access openid profile email"
)


def normalize_tenant_id(tenant_id: str) -> str:
    """Return a tenant segment for login.microsoftonline.com token URLs."""
    tenant = (tenant_id or "").strip()
    return tenant or "organizations"


def token_url_for_tenant(tenant_id: str) -> str:
    """Build v2.0 token endpoint URL for a tenant (or organizations/common)."""
    return f"https://login.microsoftonline.com/{normalize_tenant_id(tenant_id)}/oauth2/v2.0/token"


def normalize_refresh_scope(scope: str = None) -> str:
    """Ensure refresh requests include offline_access + OIDC scopes for v2.0."""
    effective = (scope or "").strip() or DEFAULT_REFRESH_SCOPE
    parts = effective.split()
    for required in ("offline_access", "openid", "profile", "email"):
        if required not in parts:
            parts.append(required)
    return " ".join(parts)


def request_device_code(tenant_id: str, client_id: str, scope: str, client_secret: str = None):
    """
    Request a new device code from Microsoft identity platform.
    Returns dict with user_code, device_code, verification_uri, message, expires_in, interval.
    """
    # For public client flows like 'az login --use-device-code', the device code
    # endpoint is typically called on /organizations/, so we ignore tenant_id here.
    url = DEVICE_AUTH_URL
    data = {
        "client_id": client_id,
        # Use full scope (ARM + offline_access + OIDC), optionally extended by caller.
        "scope": scope or FULL_SCOPE,
        "claims": CLAIMS_CP1,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(url, data=data, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()


def poll_for_tokens(tenant_id: str, client_id: str, device_code: str):
    """
    Exchange device_code for tokens. Call repeatedly until user completes auth or code expires.
    client_id must be the same public client_id used to request the device code.
    Returns (success: bool, data: dict).
    - On success (200): data has access_token, refresh_token, expires_in, scope, etc.
    - On pending: success=False, data has "error": "authorization_pending" or "slow_down"
    - On expired: success=False, data has "error": "expired_token"
    - On error: success=False, data has "error", "error_description", and optionally "error_codes", "status_code"
    """
    url = token_url_for_tenant(tenant_id)
    data = {
        "grant_type": "device_code",
        "client_id": client_id,
        "device_code": device_code,
        "scope": FULL_SCOPE,
        "claims": CLAIMS_CP1,
        "client_info": "1",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        r = requests.post(url, data=data, headers=headers, timeout=30)
    except requests.RequestException as e:
        return False, {"error": "request_failed", "error_description": str(e), "status_code": None}
    try:
        body = r.json()
    except ValueError:
        body = {
            "error": "invalid_response",
            "error_description": f"HTTP {r.status_code}: {r.text[:500] if r.text else 'empty body'}",
        }
    body["status_code"] = r.status_code

    if r.status_code == 200:
        return True, body
    error = body.get("error")
    if error in ("authorization_pending", "slow_down"):
        return False, body
    if error == "expired_token":
        return False, body
    return False, body


def is_device_code_redeemed_error(data: dict) -> bool:
    """True when Microsoft reports the device/authorization code was already used."""
    if not data:
        return False
    desc = (data.get("error_description") or "").lower()
    err = (data.get("error") or "").lower()
    codes = data.get("error_codes") or []
    code_str = " ".join(str(c) for c in codes).lower()
    if "54005" in code_str or "aadsts54005" in desc:
        return True
    if "already redeemed" in desc:
        return True
    if err in ("bad_verification_code", "invalid_grant") and (
        "redeemed" in desc or "already been used" in desc
    ):
        return True
    return False


# Backward-compatible alias used by older imports.
DEFAULT_SCOPE = DEFAULT_REFRESH_SCOPE


def refresh_access_token(tenant_id: str, refresh_token: str, scope: str = None, client_id: str = None):
    """
    Exchange a refresh token for a new access token (OAuth 2.0 v2.0).

    POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
    Body (application/x-www-form-urlencoded):
      client_id, scope, claims, client_info=1, grant_type=refresh_token, refresh_token
    """
    if not refresh_token:
        raise ValueError("refresh_token is required")
    if not client_id:
        raise ValueError("client_id is required for public-client refresh_token exchange")

    url = token_url_for_tenant(tenant_id)
    
    data = {
        "client_id": client_id,
        "scope": normalize_refresh_scope(scope),
        "claims": CLAIMS_CP1,
        "client_info": "1",
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(url, data=data, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()


def get_client_credentials_token(tenant_id: str, scope: str = "https://management.azure.com/.default"):
    """
    Get an access token using client credentials (for app-only, e.g. Graph API).
    Requires client_secret. Returns dict with access_token, expires_in.
    """
    # For now we also use the /organizations/ endpoint for client-credentials.
    url = token_url_for_tenant(tenant_id)
    data = {
        "grant_type": "client_credentials",
        "scope": scope,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(url, data=data, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()
