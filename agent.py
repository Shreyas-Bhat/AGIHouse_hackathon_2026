import json
import openai
from gatekeeper import Gatekeeper, PermissionDenied
from tools import TOOL_REGISTRY, TOOL_SCHEMAS

client = openai.OpenAI()

SYSTEM_PROMPT = """You are a personal chief-of-staff agent.
You have access to the user's calendar and can send emails on their behalf.
Complete the given task using the available tools. Be concise."""


def run_agent(task: str, gatekeeper: Gatekeeper, verbose: bool = True) -> str:
    """
    Standard tool-use agent loop using OpenAI function calling.
    Every tool call is intercepted by the gatekeeper before execution.
    """
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": task},
    ]

    max_turns = 10
    for _ in range(max_turns):
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=TOOL_SCHEMAS,
            tool_choice="auto",
        )

        choice = response.choices[0]
        finish_reason = choice.finish_reason

        if verbose:
            print(f"  [LLM] finish_reason={finish_reason}")

        if finish_reason == "stop":
            return choice.message.content or "(no text response)"

        if finish_reason != "tool_calls":
            return f"Unexpected finish_reason: {finish_reason}"

        # Append the assistant turn (with tool_calls)
        msg = choice.message
        messages.append({
            "role": "assistant",
            "content": msg.content,
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in msg.tool_calls
            ],
        })

        # Process each tool call and append a tool result message
        for tc in msg.tool_calls:
            tool_name = tc.function.name
            tool_args = json.loads(tc.function.arguments)

            if verbose:
                print(f"\n  [AGENT] Wants to call: {tool_name}({json.dumps(tool_args)})")

            tool_entry = TOOL_REGISTRY.get(tool_name)

            try:
                if tool_entry is None:
                    raise PermissionDenied(f"Unknown tool '{tool_name}'")

                result = gatekeeper.request(tool_name, tool_args, tool_entry["fn"])

                if verbose:
                    print(f"  [GATE]  APPROVED ✓")

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result),
                })

            except PermissionDenied as exc:
                if verbose:
                    print(f"  [GATE]  DENIED  ✗  — {exc}")

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": f"PERMISSION DENIED: {exc}",
                })

    return "(max turns reached — agent did not finish)"
