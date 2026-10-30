# Setup guide

Follow these steps after cloning the repo. Each person must create **their own** Google Cloud OAuth files.

`credentials.json` and `token.json` are **not** in GitHub. Never commit them.

**This project’s connected account (login target):** `mcpgatewayaccnt1@gmail.com`  
**Exfil watch inbox (not used for OAuth):** `mcpgatewayaccnt2@gmail.com`  

See [architecture.md](architecture.md) for the full mailbox model.

---

## Prerequisites

- Windows, macOS, or Linux  
- Python **3.11+**  
- A Google account for Gmail / Calendar  
- [Cursor](https://cursor.com) for the LLM  
- Git  

Optional: [uv](https://docs.astral.sh/uv/) (`pyproject.toml` / `uv.lock` are included)

---

## 1. Clone

```bash
git clone <YOUR_GITHUB_REPO_URL>
cd Security
```

---

## 2. Install dependencies

**With uv (recommended):**

```bash
uv sync
```

**With pip:**

```bash
python -m venv .venv

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate

pip install -e .
```

---

## 3. Google Cloud project

1. Open [Google Cloud Console](https://console.cloud.google.com/).  
2. Create a project (example name: `gmail-mcp-local`).  
3. Select that project.

---

## 4. Enable APIs

On the **same** project:

1. [Gmail API](https://console.cloud.google.com/apis/library/gmail.googleapis.com) → **Enable**  
2. [Google Calendar API](https://console.cloud.google.com/apis/library/calendar-json.googleapis.com) → **Enable**

---

## 5. OAuth consent screen (Testing)

1. Open [OAuth audience / consent screen](https://console.cloud.google.com/auth/audience).  
2. User type: **External**.  
3. Fill app name, support email, developer contact.  
4. Keep **Publishing status = Testing** (do not publish).  
5. Under **Test users**, add the connected account (this repo: `mcpgatewayaccnt1@gmail.com`).

If you skip test users you get: `Error 403: access_denied`.

---

## 6. Desktop OAuth client → `credentials.json`

1. [Credentials](https://console.cloud.google.com/apis/credentials) → **Create credentials** → **OAuth client ID**.  
2. Type: **Desktop app**.  
3. Download JSON → rename to `credentials.json`.  
4. Place it in the **project root** (next to `pyproject.toml`).

Shape (values will differ):

```json
{
  "installed": {
    "client_id": "...apps.googleusercontent.com",
    "project_id": "your-project-id",
    "client_secret": "...",
    "redirect_uris": ["http://localhost"]
  }
}
```

---

## 7. One-time login → `token.json`

```bash
# Windows
.\.venv\Scripts\python.exe Backend\email_server.py --login

# macOS / Linux
.venv/bin/python Backend/email_server.py --login
```

1. Browser opens → sign in as **`mcpgatewayaccnt1@gmail.com`** (connected / attacking mail).  
2. If “Google hasn’t verified this app” → **Advanced** → **Go to \<app\> (unsafe)**.  
3. Allow Gmail (read / send / compose) and Calendar events.  
4. Terminal prints `Login complete. Saved .../token.json`.

You do **not** create `token.json` by hand. If scopes change later, delete `token.json` and run `--login` again.

`mcpgatewayaccnt2@gmail.com` is only the **exfil watch** inbox for tests — do not use it for `--login` unless you intentionally change `CONNECTED_EMAIL` in `attack_generator.py`.

---

## 8. Smoke test in the terminal

```bash
.\.venv\Scripts\python.exe Backend\email_server.py
```

You should see recent inbox subjects, then the process exits.

---

## 9. Connect Cursor (LLM)

1. Edit `.cursor/mcp.json` so paths match **your** machine:

```json
{
  "mcpServers": {
    "gmail": {
      "command": "C:\\path\\to\\Security\\.venv\\Scripts\\python.exe",
      "args": [
        "C:\\path\\to\\Security\\Backend\\email_server.py",
        "--stdio"
      ]
    }
  }
}
```

2. **Settings → MCP** → enable **gmail** (connected, not error).  
3. New chat → ask `What tools are allowed?` or `Read my latest emails`.

Cursor starts the server with `--stdio`. You do not need to keep a separate terminal open for chat use.

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `403: access_denied` | Add your Gmail under **Test users** |
| Unverified app warning | **Advanced** → continue (normal for Testing) |
| Missing OAuth client file | Put `credentials.json` in project root |
| Cursor has no tools | Fix `mcp.json` paths; enable **gmail**; reload Cursor |
| Calendar / drafts fail after old login | Delete `token.json`, run `--login` again |
| `send_email` blocked | Approve via `require_user_confirm`, then retry with `confirm_token` |

Next: [tools-and-usage.md](tools-and-usage.md) or [architecture.md](architecture.md).
