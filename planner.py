import json
import openai

client = openai.OpenAI()

AVAILABLE_TOOLS = ["read_calendar", "send_email"]


def generate_plan(task: str) -> list[dict]:
    """
    Ask GPT to predict the minimal set of tool calls needed for this task.
    Returns a list of {"tool": ..., "reason": ..., "constraint": ...} dicts.
    This becomes the 'contract' the gatekeeper enforces at runtime.
    """
    prompt = f"""You are planning the safe execution of an AI agent.

Task: {task}

Available tools: {json.dumps(AVAILABLE_TOOLS)}

Produce the minimal ordered list of tool calls this agent should make.
For send_email, add a constraint: "only to addresses found in the calendar results".

Return ONLY valid JSON:
{{
  "steps": [
    {{
      "tool": "read_calendar",
      "reason": "need to know which events exist next week",
      "constraint": null
    }},
    {{
      "tool": "send_email",
      "reason": "notify attendees of cancellation",
      "constraint": "only to addresses returned by read_calendar"
    }}
  ]
}}"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
    )

    raw = response.choices[0].message.content
    return json.loads(raw)["steps"]
