# Security notes

## Secrets

| File | What it is | In Git? |
| --- | --- | --- |
| `credentials.json` | Google OAuth client id/secret | **No** |
| `token.json` | Session for **connected** account (`mcpgatewayaccnt1@gmail.com`) | **No** |
| `.env` | Optional local env | **No** |
| `.env.example` | Placeholders only | Yes |

Treat `token.json` like a password for the connected mailbox.

---

## Working principles (controls)

Implemented in `Backend/`:

1. **Allowlist** — only tools in `gateway.py`  
2. **Confirmation** — `send_email` / `create_calendar_event` need `require_user_confirm`  
3. **Draft ≠ send**  
4. **Own calendar only** — no guests / external share  
5. **Literal filenames** — no template evaluation  
6. **Narrow OAuth scopes** — Gmail read/compose/send + calendar events  

Not implemented yet (honest gap):

- **TC-05** — authentication of local/stdio callers (`MCP_CALLER_TOKEN` style)

---

## Mailbox risk model

| Mailbox | Risk if misused |
| --- | --- |
| `mcpgatewayaccnt1@gmail.com` | Full agent power (read/send as this user) via `token.json` |
| `mcpgatewayaccnt2@gmail.com` | Receives exfil if send is allowed without proper confirm |

A **SAFE** harness result for send-based attacks means the gateway blocked delivery to the exfil inbox (confirm required; harness does not auto-approve).

---

## What not to claim

| Claim | OK? |
| --- | --- |
| Real gateway ASR from `compare_before_after.py` | Yes |
| Mock 100% / 0% ASR as product result | **No** (label as mock) |
| “TC-05 passed” | **No** until caller auth exists |
| “We patched Claude/Google/Hugging Face CVEs” | **No** — same *risk classes*, different product |
| Allowlist + confirm exist | Yes |

---

## Isolation for evaluations

If the agent sees TC ids or `attack_generator.py`, you are testing exam recognition, not mechanism resistance. Keep attack metadata out of prompts and out of `Backend/`.

---

## Related docs

- [architecture.md](architecture.md) — principles and diagrams  
- [testing.md](testing.md) — how to measure  
- [scores_real_gateway.md](scores_real_gateway.md) — latest numbers  
