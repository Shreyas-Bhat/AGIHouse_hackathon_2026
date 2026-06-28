"""
Runtime credential fetcher — pulls secrets from 1Password at the moment
the gatekeeper approves a tool call. The child agent never sees raw values.

Requires:
    OP_SERVICE_ACCOUNT_TOKEN  — 1Password service account token
    OP_VAULT                  — vault name (default: Chief-of-Staff)

1Password item layout expected:
    Vault:  Chief-of-Staff
    Item:   Google-OAuth
    Fields: client_id, client_secret, refresh_token
"""

import os
import asyncio


def fetch_secret(op_reference: str) -> str:
    """Resolve a 1Password secret reference like op://vault/item/field."""
    token = os.environ.get("OP_SERVICE_ACCOUNT_TOKEN")
    if not token:
        raise RuntimeError(
            "OP_SERVICE_ACCOUNT_TOKEN not set. "
            "Create a service account at 1password.com and add the token to .env"
        )

    from onepassword.client import Client

    async def _resolve() -> str:
        client = await Client.authenticate(
            auth=token,
            integration_name="Chief of Staff Agent",
            integration_version="1.0.0",
        )
        return await client.secrets.resolve(op_reference)

    return asyncio.run(_resolve())


def get_google_credentials():
    """
    Fetch Google OAuth credentials from 1Password and return a
    google.oauth2.credentials.Credentials object ready for use.
    """
    from google.oauth2.credentials import Credentials

    vault = os.environ.get("OP_VAULT", "Chief-of-Staff")
    base = f"op://{vault}/Google-OAuth"

    return Credentials(
        token=None,
        refresh_token=fetch_secret(f"{base}/refresh_token"),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=fetch_secret(f"{base}/client_id"),
        client_secret=fetch_secret(f"{base}/client_secret"),
        scopes=[
            "https://www.googleapis.com/auth/calendar.readonly",
            "https://www.googleapis.com/auth/gmail.send",
        ],
    )
