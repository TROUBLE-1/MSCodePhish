"""Build security assessment report data for a campaign."""
import math
from datetime import datetime

from app.models import DeviceCodeSession


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


def _delivery_label(campaign) -> str:
    method = (campaign.email_delivery_method or "none").lower()
    if method == "smtp":
        if campaign.smtp_config:
            return f"SMTP ({campaign.smtp_config.name} - {campaign.smtp_config.from_email})"
        return "SMTP (no config selected)"
    if method == "azure":
        return "Microsoft Graph (Azure app)"
    if method == "api":
        return "API launch only"
    return "None (manual / API device code)"


def _session_effective_status(session, now: datetime) -> str:
    if session.status == "pending" and session.expires_at and session.expires_at <= now:
        return "expired"
    return session.status or "unknown"


def _pie_slices(items, cx=100, cy=100, r_out=72, r_in=48):
    """Build SVG donut slice paths from {label, value, color} items."""
    positive = [i for i in items if i.get("value", 0) > 0]
    total = sum(i["value"] for i in positive)
    if not total:
        return []

    slices = []
    start = -math.pi / 2
    for item in positive:
        v = item["value"]
        sweep = 2 * math.pi * v / total
        end = start + sweep
        large = 1 if sweep > math.pi else 0

        x1 = cx + r_out * math.cos(start)
        y1 = cy + r_out * math.sin(start)
        x2 = cx + r_out * math.cos(end)
        y2 = cy + r_out * math.sin(end)
        x3 = cx + r_in * math.cos(end)
        y3 = cy + r_in * math.sin(end)
        x4 = cx + r_in * math.cos(start)
        y4 = cy + r_in * math.sin(start)

        if len(positive) == 1 and v == total:
            path = (
                f"M {cx} {cy - r_out} "
                f"A {r_out} {r_out} 0 1 1 {cx - 0.001} {cy - r_out} "
                f"L {cx - 0.001} {cy - r_in} "
                f"A {r_in} {r_in} 0 1 0 {cx} {cy - r_in} Z"
            )
        else:
            path = (
                f"M {x1:.2f} {y1:.2f} "
                f"A {r_out} {r_out} 0 {large} 1 {x2:.2f} {y2:.2f} "
                f"L {x3:.2f} {y3:.2f} "
                f"A {r_in} {r_in} 0 {large} 0 {x4:.2f} {y4:.2f} Z"
            )

        slices.append(
            {
                **item,
                "path": path,
                "pct": round((v / total) * 100, 1),
            }
        )
        start = end
    return slices


def _bar_rows(items, total=None):
    """Horizontal bar chart rows with percentage width."""
    total = total or sum(i.get("value", 0) for i in items)
    rows = []
    for item in items:
        value = item.get("value", 0)
        pct = round((value / total) * 100, 1) if total else 0.0
        rows.append({**item, "pct": pct})
    return rows


def _build_executive_summary(
    campaign,
    *,
    total,
    authorized,
    tokens,
    delivered,
    success_rate,
    delivery_rate,
    status_counts,
    account_counts,
    client_name,
    delivery_label,
    risk_level,
):
    """Narrative executive summary and key finding bullets for leadership."""
    name = campaign.name or "Unnamed campaign"
    paragraphs = []
    highlights = []

    paragraphs.append(
        f"This report summarizes a controlled device-code phishing assessment for campaign "
        f"\"{name}\". The simulation used the public OAuth client \"{client_name}\" and "
        f"delivery method: {delivery_label}. Users who completed sign-in on Microsoft's device "
        f"login page would have granted refresh tokens usable for subsequent API access under "
        f"the impersonated first-party application."
    )

    if total == 0:
        paragraphs.append(
            "No device-code sessions were launched during this campaign. There are no "
            "authentication outcomes to analyze; consider re-running the assessment with "
            "targeted recipients or verifying delivery configuration."
        )
        highlights.append("Zero sessions recorded - assessment produced no measurable exposure.")
    elif authorized == 0:
        paragraphs.append(
            f"Across {total} session(s), no users completed authentication. "
            f"{delivered} phishing message(s) were delivered ({delivery_rate}% of sessions). "
            "While no credentials were captured, the attempt still validates that device-code "
            "flows can be initiated against your tenant using common Microsoft client applications."
        )
        highlights.append(
            f"No successful authentications ({total} session(s) launched, "
            f"{status_counts['expired']} expired, {status_counts['pending']} still pending)."
        )
        if status_counts["error"]:
            highlights.append(
                f"{status_counts['error']} session(s) ended in error - review delivery and client configuration."
            )
    else:
        paragraphs.append(
            f"The assessment resulted in {authorized} of {total} session(s) successfully "
            f"authenticating ({success_rate}% compromise rate). {tokens} refresh token(s) "
            f"were captured and are available for further security validation in MSCodePhish."
        )
        corp = account_counts["corporate"]
        personal = account_counts["personal"]
        if corp or personal:
            parts = []
            if corp:
                parts.append(f"{corp} corporate (work/school)")
            if personal:
                parts.append(f"{personal} personal (MSA)")
            paragraphs.append(
                "Compromised or attempted identities included "
                + " and ".join(parts)
                + " account(s), indicating which user populations accepted the device-login prompt."
            )
        highlights.append(
            f"{authorized} user(s) authenticated via device code ({success_rate}% of all sessions)."
        )
        if tokens:
            highlights.append(f"{tokens} OAuth refresh token(s) captured - treat as active credential exposure.")
        if personal:
            highlights.append(
                f"{personal} personal Microsoft account(s) involved - review consumer identity access policies."
            )
        if corp:
            highlights.append(f"{corp} corporate account(s) involved - prioritize targeted awareness and CA hardening.")

    if delivered and total:
        highlights.append(f"Phishing delivery reached {delivered} of {total} targets ({delivery_rate}% delivery rate).")

    highlights.append(f"Overall risk posture: {risk_level}.")

    return {
        "paragraphs": paragraphs,
        "highlights": highlights[:6],
    }


def _build_chart_data(status_counts, account_counts, total, delivered, authorized):
    """Chart series for session outcomes, account mix, and assessment funnel."""
    denied_other = (
        status_counts["denied"]
        + status_counts["cancelled"]
        + status_counts["other"]
    )
    outcome_items = [
        {"label": "Authorized", "value": status_counts["authorized"], "color": "#b42318"},
        {"label": "Pending", "value": status_counts["pending"], "color": "#b54708"},
        {"label": "Expired", "value": status_counts["expired"], "color": "#98a2b3"},
        {"label": "Error", "value": status_counts["error"], "color": "#d92d20"},
        {"label": "Denied / other", "value": denied_other, "color": "#667085"},
    ]
    account_items = [
        {"label": "Corporate", "value": account_counts["corporate"], "color": "#175cd3"},
        {"label": "Personal (MSA)", "value": account_counts["personal"], "color": "#5925dc"},
        {"label": "Unknown", "value": account_counts["unknown"], "color": "#98a2b3"},
    ]
    funnel_items = [
        {"label": "Sessions launched", "value": total, "color": "#0b3d6b"},
        {"label": "Phishing emails sent", "value": delivered, "color": "#1570ef"},
        {"label": "Successful auth", "value": authorized, "color": "#b42318"},
    ]
    funnel_max = max((i["value"] for i in funnel_items), default=0) or 1

    return {
        "outcome_slices": _pie_slices(outcome_items),
        "outcome_total": total,
        "outcome_legend": [i for i in outcome_items if i["value"] > 0],
        "account_slices": _pie_slices(account_items),
        "account_total": sum(account_counts.values()),
        "account_legend": [i for i in account_items if i["value"] > 0],
        "funnel_bars": _bar_rows(funnel_items, total=funnel_max),
    }


def _assess_device_code_posture(sessions):
    """Best-effort CA posture using the first captured token with Graph access."""
    token_id = None
    for session in sessions or []:
        if session.captured_token is not None:
            token_id = session.captured_token.id
            break
    if not token_id:
        return {
            "status": "unavailable",
            "label": "Not assessed",
            "summary": "No captured token available to query Conditional Access policies.",
            "error": None,
        }
    try:
        from app.entra_enum import fetch_authentication_flows_posture
        data, err = fetch_authentication_flows_posture(token_id)
        if err or not data:
            return {
                "status": "unavailable",
                "label": "Unable to assess",
                "summary": err or "Could not evaluate Conditional Access authentication flows.",
                "error": err,
            }
        posture = data.get("posture") or {}
        return {
            "status": posture.get("status") or "unavailable",
            "label": posture.get("label") or "Unable to assess",
            "summary": posture.get("summary") or "",
            "learn_more": posture.get("learn_more"),
            "detection_hint": posture.get("detection_hint"),
            "targeting_count": posture.get("targeting_count"),
            "enabled_block_count": posture.get("enabled_block_count"),
            "enabled_block_policies": posture.get("enabled_block_policies") or [],
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "unavailable",
            "label": "Unable to assess",
            "summary": str(exc),
            "error": str(exc),
        }


def _device_code_posture_recommendations(posture: dict) -> list:
    status = (posture or {}).get("status")
    learn = (posture or {}).get("learn_more") or (
        "https://learn.microsoft.com/en-us/entra/identity/conditional-access/"
        "policy-block-authentication-flows"
    )
    items = []
    if status == "protected":
        items.append(
            "Tenant appears protected: an enabled Conditional Access policy blocks device code "
            "for all users. Validate exclusions and keep monitoring for report-only gaps."
        )
    elif status == "partial":
        items.append(
            "Device code is only partially blocked. Expand Conditional Access Authentication flows "
            f"→ Device code → Block to all users (with minimal break-glass exclusions). See {learn}"
        )
    elif status == "report_only":
        items.append(
            "Device code block policies are report-only. Review sign-in impact, then move them to "
            f"Enabled. See {learn}"
        )
    elif status == "unprotected":
        items.append(
            "CRITICAL: No enabled Conditional Access policy blocks device code flow. Create a policy "
            "under Conditions → Authentication flows → Device code → Grant → Block access. "
            f"See {learn}"
        )
    else:
        items.append(
            "Enforce Conditional Access Authentication flows to block device code for users who do "
            f"not explicitly require it. See {learn}"
        )

    items.append(
        "Secondary risk: if device code remains allowed, attackers may use it to complete "
        "Authenticator or passkey registration on a remote device."
    )
    items.append(
        (posture or {}).get("detection_hint")
        or (
            "Monitor Entra sign-in logs for device code authentications and unexpected first-party "
            "client IDs; alert on Authenticator/passkey registration soon after device-code sign-in."
        )
    )
    return items


def build_campaign_report(campaign, sessions=None, now=None):
    """Aggregate campaign metrics and rows for the assessment report."""
    now = now or datetime.utcnow()
    if sessions is None:
        sessions = (
            DeviceCodeSession.query.filter_by(campaign_id=campaign.id)
            .order_by(DeviceCodeSession.created_at.desc())
            .all()
        )

    status_counts = {
        "authorized": 0,
        "pending": 0,
        "expired": 0,
        "error": 0,
        "denied": 0,
        "cancelled": 0,
        "other": 0,
    }
    account_counts = {"personal": 0, "corporate": 0, "unknown": 0}
    authorized_rows = []
    other_rows = []

    for session in sessions:
        effective = _session_effective_status(session, now)
        if effective in status_counts:
            status_counts[effective] += 1
        else:
            status_counts["other"] += 1

        acct = (session.account_type or "").lower()
        if acct in account_counts:
            account_counts[acct] += 1
        else:
            account_counts["unknown"] += 1

        row = {
            "id": session.id,
            "target": session.display_target,
            "target_email": session.target_email or session.user_email or "-",
            "user_email": session.user_email or "-",
            "display_name": session.user_display_name or session.user_given_name or "-",
            "account_type": session.account_type or "-",
            "tenant_id": session.tenant_id or "-",
            "source_ip": session.source_ip or "-",
            "status": effective,
            "email_sent": session.email_sent,
            "post_auth_email_sent": session.post_auth_email_sent,
            "created_at": session.created_at,
            "error_message": session.error_message,
            "has_token": session.captured_token is not None,
        }
        if effective == "authorized":
            authorized_rows.append(row)
        else:
            other_rows.append(row)

    total = len(sessions)
    authorized = status_counts["authorized"]
    delivered = sum(1 for s in sessions if s.email_sent)
    tokens = sum(1 for s in sessions if s.captured_token is not None)

    success_rate = round((authorized / total) * 100, 1) if total else 0.0
    delivery_rate = round((delivered / total) * 100, 1) if total else 0.0

    has_pending = status_counts["pending"] > 0
    if has_pending:
        ui_status = "running"
    elif total:
        ui_status = "completed"
    else:
        ui_status = campaign.status or "draft"

    if authorized == 0:
        risk_level = "Low (no successful authentications)"
        risk_class = "risk-low"
    elif success_rate >= 50:
        risk_level = "Critical - high device-code compromise rate"
        risk_class = "risk-critical"
    elif success_rate >= 25:
        risk_level = "High - multiple users authenticated"
        risk_class = "risk-high"
    else:
        risk_level = "Medium - limited successful authentications"
        risk_class = "risk-medium"

    client_id = (campaign.public_client_id or "").strip()
    device_code_posture = _assess_device_code_posture(sessions)
    recommendations = _device_code_posture_recommendations(device_code_posture) + [
        "Require phishing-resistant MFA (FIDO2 / Windows Hello for Business) for privileged and high-risk users.",
        "Educate users on Microsoft device-login prompts and verify app name shown during code entry.",
        "Restrict legacy authentication and review apps with offline_access / refresh token issuance.",
    ]
    if account_counts["personal"]:
        recommendations.append(
            "Review personal Microsoft account (MSA) sign-ins to corporate resources - consider blocking consumer identities where not required."
        )
    if authorized:
        recommendations.insert(
            0,
            f"Immediately rotate credentials and revoke refresh tokens for {authorized} compromised account(s) identified in this assessment.",
        )

    executive = _build_executive_summary(
        campaign,
        total=total,
        authorized=authorized,
        tokens=tokens,
        delivered=delivered,
        success_rate=success_rate,
        delivery_rate=delivery_rate,
        status_counts=status_counts,
        account_counts=account_counts,
        client_name=_client_display_name(client_id),
        delivery_label=_delivery_label(campaign),
        risk_level=risk_level,
    )
    charts = _build_chart_data(status_counts, account_counts, total, delivered, authorized)

    return {
        "campaign": campaign,
        "generated_at": now,
        "ui_status": ui_status,
        "total_sessions": total,
        "authorized_count": authorized,
        "tokens_captured": tokens,
        "emails_delivered": delivered,
        "success_rate": success_rate,
        "delivery_rate": delivery_rate,
        "status_counts": status_counts,
        "account_counts": account_counts,
        "authorized_rows": authorized_rows,
        "other_rows": other_rows,
        "risk_level": risk_level,
        "risk_class": risk_class,
        "delivery_label": _delivery_label(campaign),
        "client_id": client_id,
        "client_name": _client_display_name(client_id),
        "recommendations": recommendations,
        "device_code_posture": device_code_posture,
        "executive": executive,
        "charts": charts,
    }
