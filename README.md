# MCP Security Gateway

Least-privilege MCP bridge between **Cursor’s LLM** and **Gmail + Google Calendar**.

The model can read mail, save drafts, send mail (with confirmation), check your calendar, create events on **your** calendar only (with confirmation), and store attachments as **literal** filenames. Finance, payroll, passwords, and shell access are not exposed.

**Working principle:** untrusted content is data; privileged actions need an allowlisted tool and, for send/calendar-create, a human confirm token.

| Role | Address |
| --- | --- |
| Connected / attacking mail (OAuth) | `aswinm2k4@gmail.com` |
| Exfil / attacked inbox (watch) | `aswinmmsa@gmail.com` |

---

## Documentation

| Doc | Contents |
| --- | --- |
| [docs/overview.md](docs/overview.md) | What / why / principles |
| [docs/setup.md](docs/setup.md) | Clone → OAuth → Cursor |
| [docs/architecture.md](docs/architecture.md) | System architecture + working principles |
| [docs/tools-and-usage.md](docs/tools-and-usage.md) | Tools, CLI, chat |
| [docs/testing.md](docs/testing.md) | 16-attack harness |
| [docs/scores_real_gateway.md](docs/scores_real_gateway.md) | Latest real ASR |
| [docs/security.md](docs/security.md) | Secrets + reporting honesty |

Index: [`docs/README.md`](docs/README.md). Also [`implementation.md`](implementation.md) / [`test.md`](test.md) point into `docs/`.

---

## Quick start

1. Clone and install (`uv sync` or venv + `pip install -e .`).  
2. Enable **Gmail API** + **Calendar API**.  
3. OAuth consent = **Testing**; add `aswinm2k4@gmail.com` as test user.  
4. Desktop OAuth client → `credentials.json` in project root.  
5. Login **as the connected account**:

```powershell
.\.venv\Scripts\python.exe Backend\email_server.py --login
```

6. Edit `.cursor/mcp.json` → **Settings → MCP** → enable **gmail**.  
7. Chat: `What tools are allowed?` / `Read my latest emails`.

Details: [docs/setup.md](docs/setup.md).

---

## Tools

| Tool | Confirm? | Notes |
| --- | --- | --- |
| `get_my_identity` | No | Trusted directory department |
| `list_allowed_tools` | No | Filtered by department |
| `require_user_confirm` | No | Starts approval plan |
| `read_latest_emails` | No | Needs `mail:use` |
| `create_email_draft` | No | |
| `send_email` | **Yes** | Execution token |
| `get_calendar_availability` | No | |
| `create_calendar_event` | **Yes** | Execution token |
| `store_attachment` | No | Literal filenames |
| `read_project_report` | No | Engineering only |
| `read_salary_record` | No | HR only |
| `read_financial_report` | No | Finance only |
| `read_campaign_insights` | No | Marketing only |

---

## Commands

| Command | Purpose |
| --- | --- |
| `python Backend/email_server.py --login` | Create `token.json` |
| `python Backend/email_server.py` | Print inbox |
| `python Backend/email_server.py --stdio` | MCP for Cursor / harness |
| `python Backend/email_server.py --serve` | Optional HTTP MCP |

---

## Testing (real gateway, all 16 cases)

```powershell
cd testcases\extracted
Remove-Item Env:MCP_HARNESS_TARGET -ErrorAction SilentlyContinue
C:\Capstone\Security\.venv\Scripts\python.exe compare_before_after.py
```

- Default: **real MCP only** (no mock)  
- From = `aswinm2k4@gmail.com` · exfil To = `aswinmmsa@gmail.com`  
- Writes `docs/scores_real_gateway.md` + `results/after_gateway.json`  

Optional mock baseline: `python compare_before_after.py --with-baseline`

---

## Layout

```text
Security/
  README.md
  docs/                     architecture, testing, scores, …
  Backend/
    email_server.py         MCP entry
    gateway.py              allowlist + confirm
    attachments.py          literal file store
  testcases/extracted/      16-attack harness (real by default)
  results/                  JSON scores
  .cursor/mcp.json
  credentials.json          gitignored
  token.json                gitignored (aswinm2k4 session)
```

---

## Security

- Never commit `credentials.json` or `token.json`.  
- Do not claim TC-05 SAFE without caller auth.  
- Do not report mock ASR as the product result.  

More: [docs/security.md](docs/security.md) · [docs/architecture.md](docs/architecture.md).
