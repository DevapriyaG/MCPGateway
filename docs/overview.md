# Overview

## What this project is

A **least-privilege MCP Security Gateway** that sits between an LLM (Cursor) and Google APIs so the model can safely use a **small, fixed** set of tools:

- Read Gmail inbox subjects  
- Save Gmail drafts  
- Send Gmail **only after user confirmation**  
- Read / create events on **your** primary Google Calendar (create needs confirmation)  
- Store local attachments with **literal** filenames  

It does **not** expose finance, payroll, passwords, shell, or other people’s calendars.

---

## Working principle (one sentence)

**Untrusted content is data; the prompt guides the LLM, but the gateway enforces caller auth, trusted department policy, and (for send/calendar-create) a human-bound execution token.**

---

## Mailbox model

| Role | Address | You use it to… |
| --- | --- | --- |
| Connected / attacking mail | `aswinm2k4@gmail.com` | OAuth login; agent operates as this user; attack **From** |
| Exfil / attacked inbox | `aswinmmsa@gmail.com` | See whether attack forwards arrived |

---

## Why it exists (capstone)

Agents that read email face **prompt injection** and **over-privilege** (same *classes* of risk as incidents involving Claude + Google Workspace or Hugging Face WebFetch — not the same CVEs).

This project shows:

1. A realistic multi-tool agent (mail + calendar + attachments)  
2. A **gateway** (allowlist + confirmation + literal store)  
3. A **16-attack harness** that reports **Attack Success Rate (ASR)** against the **real** MCP gateway by default  

Latest style of result (real gateway): high defense rate after allowlist + confirm + caller auth; department policy adds HR/Finance/Engineering/Marketing stubs gated by `policy.json`.

---

## Key ideas

| Idea | Meaning |
| --- | --- |
| **MCP** | Cursor (or harness) talks to `Backend/email_server.py` over stdio |
| **Allowlist** | Only tools in `gateway.py` exist |
| **Confirmation** | High-risk tools need `require_user_confirm` + `confirm_token` |
| **Data ≠ instructions** | Bodies/filenames are not commands |
| **ASR** | % of cases where the attacker goal was met — **lower is better** |

---

## What is built

| Piece | Status |
| --- | --- |
| Gmail + Calendar MCP tools | Working |
| Gateway allowlist + confirm | Working |
| Literal attachment store | Working |
| Cursor MCP config | Working |
| 16-case harness vs **real** gateway | Working (default) |
| Optional mock baseline (`--with-baseline`) | Working |
| Automated scoring of Cursor chat LLM | Manual only (paste payloads blind) |

---

## Documentation map

| Doc | Contents |
| --- | --- |
| [setup.md](setup.md) | Clone → OAuth → Cursor |
| [architecture.md](architecture.md) | Diagrams, principles, file map |
| [tools-and-usage.md](tools-and-usage.md) | Tools and day-to-day use |
| [testing.md](testing.md) | How to run the 16 attacks |
| [scores_real_gateway.md](scores_real_gateway.md) | Latest real-run scores |
| [security.md](security.md) | Secrets and honest reporting |
