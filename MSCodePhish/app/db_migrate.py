"""Lightweight schema patches for SQLite (create_all does not add columns)."""
from sqlalchemy import inspect, text


def ensure_schema(db):
    """Add columns introduced after initial deploy."""
    engine = db.engine
    insp = inspect(engine)

    def _cols(table):
        if table not in insp.get_table_names():
            return set()
        return {c["name"] for c in insp.get_columns(table)}

    patches = [
        ("campaigns", "send_post_auth_email", "BOOLEAN DEFAULT 0"),
        ("campaigns", "post_auth_email_subject", "VARCHAR(512)"),
        ("campaigns", "post_auth_email_body_html", "TEXT"),
        ("device_code_sessions", "post_auth_email_sent", "BOOLEAN DEFAULT 0"),
        ("device_code_sessions", "post_auth_email_sent_at", "DATETIME"),
        ("device_code_sessions", "user_email", "VARCHAR(256)"),
        ("device_code_sessions", "user_display_name", "VARCHAR(256)"),
        ("device_code_sessions", "user_id", "VARCHAR(256)"),
        ("device_code_sessions", "tenant_id", "VARCHAR(256)"),
        ("device_code_sessions", "user_given_name", "VARCHAR(256)"),
        ("device_code_sessions", "user_family_name", "VARCHAR(256)"),
        ("device_code_sessions", "account_type", "VARCHAR(32)"),
        ("device_code_sessions", "identity_provider", "VARCHAR(64)"),
        ("captured_tokens", "user_given_name", "VARCHAR(256)"),
        ("captured_tokens", "user_family_name", "VARCHAR(256)"),
        ("captured_tokens", "account_type", "VARCHAR(32)"),
        ("captured_tokens", "identity_provider", "VARCHAR(64)"),
    ]

    for table, col, col_type in patches:
        if col in _cols(table):
            continue
        with engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
