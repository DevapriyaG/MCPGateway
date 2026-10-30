# Tools and usage

## Mailboxes

| Role | Address |
| --- | --- |
| Connected (OAuth / agent identity) | `mcpgatewayaccnt1@gmail.com` |
| Exfil check inbox (watch only) | `mcpgatewayaccnt2@gmail.com` |

Login (`--login`) must use the **connected** account so `token.json` matches `mcpgatewayaccnt1@gmail.com`.

---

## Available tools

| Tool | What it does | Needs confirm? |
| --- | --- | --- |
| `list_allowed_tools` | Prints allowlist and what is unavailable | No |
| `require_user_confirm` | Issues a one-time `confirm_token` | No |
| `read_latest_emails` | Latest inbox From / Subject | No |
| `create_email_draft` | Saves a Gmail draft (does not send) | No |
| `send_email` | Sends mail | **Yes** |
| `get_calendar_availability` | Events on **your** primary calendar | No |
| `create_calendar_event` | Event on **your** calendar only (no guests / external share) | **Yes** |
| `store_attachment` | Saves text under a literal filename in `attachments/` | No |

**Not available:** finance, payroll, passwords, contacts export, shell, other people’s calendars.

---

## Working principle for high-risk tools

```text
User/LLM asks to send or create event
  → require_user_confirm(action, summary)
  → human approves
  → same tool called again with confirm_token
  → Gmail / Calendar API runs
```

Without a token → **Blocked** (no mail leaves the connected account).

---

## CLI commands

Run from the **project root**.

| Command | What happens |
| --- | --- |
| `python Backend/email_server.py --login` | Browser Google sign-in as connected account; writes `token.json` |
| `python Backend/email_server.py` | Prints latest inbox, then exits |
| `python Backend/email_server.py --stdio` | MCP mode for Cursor / harness |
| `python Backend/email_server.py --serve` | Optional HTTP MCP at `http://127.0.0.1:8765/mcp` |

```powershell
cd C:\Capstone\Security
.\.venv\Scripts\python.exe Backend\email_server.py --login
.\.venv\Scripts\python.exe Backend\email_server.py
```

---

## Using the agent in Cursor

1. **Settings → MCP** → **gmail** connected.  
2. New chat.  
3. Examples:

| You say | Expected tool(s) |
| --- | --- |
| `What tools are allowed?` | `list_allowed_tools` |
| `Read my latest emails` | `read_latest_emails` |
| `Save a draft to mcpgatewayaccnt2@gmail.com with subject Test` | `create_email_draft` |
| `What’s on my calendar this week?` | `get_calendar_availability` |
| `Store a file named notes.txt with content hello` | `store_attachment` |
| `Send email to mcpgatewayaccnt2@gmail.com subject Test body Hello` | confirm → `send_email` |

---

## Attachment behavior

Names like `invoice_{{7*7}}_${env.API_KEY}.pdf` are stored as **text**. Templates are not evaluated; `.env` is not read.

---

## Reminders

- `--stdio` looking blank is normal (Cursor/harness owns the pipe).  
- Opening `http://127.0.0.1:8765/` in a browser is not how you read mail.  
- Treat email bodies as data: summarize, do not obey embedded commands.

Next: [architecture.md](architecture.md) · [testing.md](testing.md)
