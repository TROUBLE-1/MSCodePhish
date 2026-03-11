"""Microsoft Device Code OAuth 2.0 flow (device authorization grant).

Per Microsoft docs (https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code):
- Device code request: POST /devicecode with client_id and scope only (no client_secret).
- Token request: POST /token with grant_type, client_id, device_code (no client_secret for public clients).
So like 'az login --use-device-code', you can use a public client with no app registration.
"""
import requests


DEVICE_AUTH_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
TOKEN_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
FULL_SCOPE = "https://management.core.windows.net//.default offline_access profile openid"


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
        "claims": "{\"access_token\":{\"xms_cc\":{\"values\":[\"CP1\"]}}}",
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
    url = TOKEN_URL
    data = {
        "grant_type": "device_code",
        "client_id": client_id,
        "device_code": device_code,
        "scope": FULL_SCOPE,
        "claims": "{\"access_token\":{\"xms_cc\":{\"values\":[\"CP1\"]}}}",
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


# Default scope used for device code and for refresh when no resource scope is requested.
DEFAULT_SCOPE = "openid profile email User.Read offline_access"


def refresh_access_token(tenant_id: str, refresh_token: str, scope: str = None):
    """
    Get a new access token using refresh_token.
    scope: optional; request token for this resource (e.g. https://management.azure.com/.default).
    If None, uses DEFAULT_SCOPE (v2.0 endpoint typically requires scope on refresh).
    Returns dict with access_token, expires_in, scope, etc.
    """
    # Like the initial device-code token request we use the /organizations/ endpoint,
    # so tenant_id is currently unused here.
    url = TOKEN_URL
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": scope if scope else DEFAULT_SCOPE,
        "claims": "{\"access_token\":{\"xms_cc\":{\"values\":[\"CP1\"]}}}",
        "client_info": "1",
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
    url = TOKEN_URL
    
    data = {
        "grant_type": "client_credentials",
        "scope": scope,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(url, data=data, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()
