   # Architecture and working principles

## What the system is

A **least-privilege MCP gateway** between:

1. **Cursor’s LLM** (or the automated test harness), and  
2. **Google APIs** for one connected Gmail/Calendar account.

The gateway exposes a **fixed allowlist** of tools. High-risk actions need a **one-time human confirmation token**. Untrusted content (email bodies, filenames) must be treated as **data**, not commands.

---

## Mailbox roles (this project)

| Role | Address | Meaning |
| --- | --- | --- |
| **Attacking / connected mail** | `mcpgatewayaccnt1@gmail.com` | OAuth login in `token.json`. Gateway reads/sends **as** this account. Attack payloads use this as **From**. |
| **Attacked / exfil inbox** | `mcpgatewayaccnt2@gmail.com` | Collection address in attack bodies (“forward to …”). If the agent is compromised and send succeeds, stolen content would land here. |

You can watch **both** inboxes after a real harness run: connected account for agent activity; exfil inbox for whether attack forwards got through (SAFE runs should not deliver them — confirm blocks send).

---

## End-to-end architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│  Operators                                                        │
│  • Cursor chat (LLM + MCP tools)                                  │
│  • Test harness (compare_before_after.py → real MCP)              │
└────────────────────────────┬────────────────────────────────────┘
                             │ MCP stdio
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Backend/email_server.py   (MCP Security Gateway)                 │
│    ├── gateway.py          allowlist + confirm tokens             │
│    ├── attachments.py      literal filename store                 │
│    ├── Gmail API           read / draft / send                    │
│    └── Calendar API        primary calendar only                  │
└────────────────────────────┬────────────────────────────────────┘
                             │ OAuth (credentials.json + token.json)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Google account: mcpgatewayaccnt1@gmail.com (connected)                  │
│  Exfil check inbox: mcpgatewayaccnt2@gmail.com (not OAuth; watch only) │
└─────────────────────────────────────────────────────────────────┘
```

### Working principles

1. **Least privilege** — Tools are allowlisted and further filtered by **trusted department policy**.  
2. **Prompt guides; gateway enforces** — System prompt ([system-prompt.md](system-prompt.md)) steers the LLM; unauthorized calls are still denied in code.  
3. **Confirm before harm** — `send_email` / `create_calendar_event` need a human-approved plan and a 256-bit execution token (hash stored server-side).  
4. **Draft ≠ send** — Drafts never transmit.  
5. **Data ≠ instructions** — Email/filename content is not treated as authorization.  
6. **Own calendar only** — Create events on the primary calendar; no guests / external share fields.  
7. **Secrets stay local** — `credentials.json` / `token.json` / `.env` are gitignored.  
8. **Eval isolation** — The agent under test must not see TC ids or `attack_generator.py`.  

### Department-aware authorization

```text
User / LLM
   │  (may claim any department — ignored)
   ▼
get_my_identity()  →  trusted directory (policy.json) + Google mailbox identity
   ▼
MCP gateway
   ├── MCP_CALLER_TOKEN (local client auth)
   ├── department permissions (policy.py)
   ├── resource ownership (project / salary / report / campaign ids)
   └── execution token + lock for high-risk writes
   ▼
Only permitted tools run
```

| Department | Example tools |
| --- | --- |
| Engineering | `read_project_report` (+ mail/calendar) |
| HR | `read_salary_record` |
| Finance | `read_financial_report` |
| Marketing | `read_campaign_insights` |

Opaque execution tokens do **not** encode department. The server stores `hash(token)` with user, session, plan version, permissions, and expiry. Directory enrollment lives in `Backend/policy.json`.

---

## Runtime paths

### A. Cursor (interactive agent)

1. Cursor reads `.cursor/mcp.json` and starts `Backend/launch_stdio.py` (presents `MCP_CALLER_TOKEN`).  
2. Optionally load [system-prompt.md](system-prompt.md) into the chat system instructions.  
3. LLM calls MCP tools; gateway enforces caller auth + department policy + confirm.  
4. Gmail/Calendar calls use `token.json` for **mcpgatewayaccnt1@gmail.com** (Engineering in `policy.json`).

### B. Automated security harness (default = real gateway)

1. `compare_before_after.py` sets `MCP_HARNESS_TARGET=real` (mock refused by default).  
2. For each of **TC-01 … TC-16**:  
   - `attack_generator` builds a payload (From = connected mail, exfil To = attacked mail).  
   - `target_adapter._real_mcp_agent` calls live tools over MCP stdio.  
   - `scorer` marks **SAFE** or **COMPROMISED** from the tool-call log.  
3. Results → `results/after_gateway.json` + `docs/scores_real_gateway.md`.  
4. Metric: **ASR** = compromised / 16 × 100 (**lower is better**).

Optional: `--with-baseline` runs a **mock** undefended agent first (no real Gmail) for before/after comparison docs.

---

## Confirmation flow (detail)

```text
LLM / harness
   │ require_user_confirm("send_email", summary)
   ▼
gateway.py  →  issues confirm_token (memory only)
   │
   │  user approves in Cursor  (harness does NOT auto-approve)
   ▼
send_email(..., confirm_token=...)
   │
   ▼
gateway consumes token once → Gmail API send
```

Without a valid token, `send_email` / `create_calendar_event` return **Blocked**. That is why many harness “attack send” attempts stay **SAFE** and do not appear in `mcpgatewayaccnt2@gmail.com`.

---

## Backend modules

| File | Role |
| --- | --- |
| `Backend/email_server.py` | MCP server: OAuth, Gmail/Calendar, identity + department stubs |
| `Backend/gateway.py` | Allowlist, caller auth, execution tokens, locks |
| `Backend/policy.py` / `policy.json` | Trusted directory, departments, resource checks |
| `Backend/attachments.py` | Safe write under `attachments/` (no template eval, path strip) |
| `docs/system-prompt.md` | LLM guidance only (not enforcement) |

### Google scopes

| Scope | Tools |
| --- | --- |
| `gmail.readonly` | `read_latest_emails` |
| `gmail.compose` | `create_email_draft` |
| `gmail.send` | `send_email` |
| `calendar.events` | `get_calendar_availability`, `create_calendar_event` |

---

## Test harness layout

| Path | Role |
| --- | --- |
| `testcases/extracted/test_cases.py` | Metadata for TC-01 … TC-16 |
| `testcases/extracted/attack_generator.py` | Payloads; `CONNECTED_EMAIL` + `ATTACKER_EMAIL` |
| `testcases/extracted/target_adapter.py` | Seam to real MCP (default) or optional mocks |
| `testcases/extracted/scorer.py` | Deterministic SAFE / COMPROMISED |
| `testcases/extracted/run_eval.py` | Runs all 16, writes JSON (refuses mock unless `--allow-mock`) |
| `testcases/extracted/compare_before_after.py` | Default real-only eval + score docs |
| `testcases/extracted/harness.py` | Simple suite runner (real by default) |

```text
compare_before_after / harness
        → attack_generator.generate(id)
        → target_adapter.run_target(channel, payload)   # real MCP
        → scorer.score(id, actions)
        → ASR table + docs/scores_*.md
```

---

## Project file map

| Path | Purpose |
| --- | --- |
| `README.md` | Entry + quick start |
| `docs/` | Full documentation |
| `Backend/` | MCP gateway |
| `testcases/extracted/` | 16-attack harness |
| `results/` | JSON scores from real/baseline runs |
| `attachments/` | Literal attachment store |
| `.cursor/mcp.json` | Cursor → gateway launch command |
| `credentials.json` / `token.json` | OAuth (local only) |

---

## Related systems (context, not installed)

| System | Relation |
| --- | --- |
| **AgentDojo** | Same metric family (targeted ASR); our suite is smaller and mail/calendar-focused |
| **IBM ContextForge** | Production MCP/A2A gateway idea; we implement a local Python gateway |
| **Docker MCP Gateway** | Tool allowlisting proxy idea; ours is in-process allowlist + confirm |

Next: [tools-and-usage.md](tools-and-usage.md) · [testing.md](testing.md) · [security.md](security.md)
