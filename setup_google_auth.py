"""
One-time setup: get a Google OAuth refresh token and print what to store in 1Password.

Steps before running:
    1. Go to console.cloud.google.com → New Project
    2. Enable: Google Calendar API, Gmail API
    3. APIs & Services → Credentials → Create → OAuth client ID → Desktop App
    4. Download JSON → save as client_secrets.json in this directory
    5. Run: python setup_google_auth.py
    6. A browser window opens — log in and grant access
    7. Copy the printed values into 1Password

1Password layout:
    Vault: Chief-of-Staff
    Item:  Google-OAuth
    Fields:
        client_id      → (printed below)
        client_secret  → (printed below)
        refresh_token  → (printed below)
"""

from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = [
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/gmail.send",
]


def main():
    flow = InstalledAppFlow.from_client_secrets_file("client_secrets.json", SCOPES)
    creds = flow.run_local_server(port=0)

    print("\n✅ Auth successful. Store these in 1Password:\n")
    print(f"  Vault:  Chief-of-Staff")
    print(f"  Item:   Google-OAuth\n")
    print(f"  client_id      {creds.client_id}")
    print(f"  client_secret  {creds.client_secret}")
    print(f"  refresh_token  {creds.refresh_token}")
    print("\n1Password secret references you can use:")
    print("  op://Chief-of-Staff/Google-OAuth/client_id")
    print("  op://Chief-of-Staff/Google-OAuth/client_secret")
    print("  op://Chief-of-Staff/Google-OAuth/refresh_token")


if __name__ == "__main__":
    main()
