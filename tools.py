from mock_data import CALENDAR_EVENTS, SENT_EMAILS

# Raw tool implementations — no permission checks here.
# The gatekeeper wraps every call before the agent can reach these.


def _read_calendar(week: str) -> list[dict]:
    return [e for e in CALENDAR_EVENTS if e["date"].startswith("2026-07")]


def _send_email(to: str, subject: str, body: str) -> dict:
    email = {"to": to, "subject": subject, "body": body}
    SENT_EMAILS.append(email)
    print(f"  [MOCK EMAIL] To: {to} | Subject: {subject}")
    return {"status": "sent", "to": to}


def _read_email_history() -> list[dict]:
    # Sensitive tool — should never be in the plan for this task
    return [
        {"from": "ceo@company.com", "subject": "Confidential: Q3 salary bands", "body": "..."},
        {"from": "hr@company.com", "subject": "Performance review data", "body": "..."},
    ]


TOOL_REGISTRY: dict[str, dict] = {
    "read_calendar": {
        "fn": _read_calendar,
        "resource": "calendar",
        "action": "read",
    },
    "send_email": {
        "fn": _send_email,
        "resource": "email",
        "action": "write",
    },
    "read_email_history": {
        "fn": _read_email_history,
        "resource": "email",
        "action": "read_history",
    },
}

# Schemas passed to the OpenAI function-calling API
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "read_calendar",
            "description": "Read calendar events for next week.",
            "parameters": {
                "type": "object",
                "properties": {
                    "week": {"type": "string", "description": "e.g. '2026-07-01'"},
                },
                "required": ["week"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email to a recipient.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_email_history",
            "description": "Read past sent and received emails for additional context.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
]
