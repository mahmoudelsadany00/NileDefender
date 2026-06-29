# 🚀 NileDefender AI IDOR Agent — Setup Guide

## Prerequisites

**Linux:**
```bash
sudo apt install docker.io docker-compose -y
sudo systemctl start docker
```

**Windows / Mac:**
- Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) and start it

**Also required:**
- OpenAI API Key (explained in Step 4)

---

## Step 1: Add your API Keys

Open `config.ini` and configure your keys:

```ini
[API_KEYS]
openai = YOUR_OPENAI_API_KEY_HERE
N8N_WEBHOOK_URL = http://n8n:5678/webhook/idor
```

> The `N8N_WEBHOOK_URL` is already set correctly — don't change it.

---

## Step 2: Start the project

```bash
docker compose up -d --build
```

Wait 2–3 minutes for both containers to initialize, then open:
- **Dashboard:** http://localhost:5000
- **n8n:** http://localhost:5677

> **Docker Networking Note:** The NileDefender container uses `host.docker.internal` internally to reach services on your host machine (e.g., bWAPP on `localhost`). All URLs are automatically normalized to `localhost` for the dashboard UI — you don't need to configure anything.

---

## Step 3: Create an n8n account

When you first open http://localhost:5677 you'll see a registration page.

1. Enter any **First Name / Last Name**
2. Enter any **Email** (doesn't have to be real)
3. Choose a **Password**
4. Click **Get started**
5. On the next page click **Skip** or **Get started for free**

---

## Step 4: Import the Workflow

1. From the left sidebar click **Workflows**
2. Click **Add Workflow** or the **+** button
3. Click **...** (three dots) → **Import from file**
4. Select the file **`agent_idor.json`** (included in the project root)
5. Press **Save** (Ctrl+S)

---

## Step 5: Add your OpenAI API Key

### a) Get your API Key
- Go to https://platform.openai.com/api-keys
- Click **Create new secret key**
- Copy the key (starts with `sk-...`)

### b) Add the key inside the Workflow
1. Open the imported Workflow
2. Click on the **OpenAI Chat Model** node
3. Under **Credential** click **Create new credential**
4. Paste the API Key in the **API Key** field
5. Click **Save**

> The workflow uses **gpt-4o-mini** by default. You can change the model in the OpenAI Chat Model node if desired.

---

## Step 6: Activate the Workflow

Click the **Inactive** toggle (top right) to switch it to **Active** ✅

---

## ✅ You're ready!

Now run a **Full Scan** (Vulnerability Scan → Full mode) from the Dashboard on any target:

- Static scanners run first (SQL Injection, XSS, Path Traversal, HTML Injection, Command Injection)
- The AI Agent automatically activates and tests for **IDOR** vulnerabilities
- When finished, the scan status changes to **Completed** automatically
- You can also run a **Custom Scan** and select only the **IDOR** module

---

## 🔄 n8n Workflow Architecture

The `agent_idor.json` workflow contains these nodes:

| Node | Description |
|------|-------------|
| **Webhook** | Receives `POST /webhook/idor` with `scan_id` and `cookie` |
| **get_endpoints2** | Fetches endpoints from NileDefender API (`?docker=1` for Docker-translated URLs) |
| **Code in JavaScript** | Filters endpoints for IDOR-relevant targets (deduplication + keyword matching) |
| **If** | Checks if any IDOR-relevant endpoints were found |
| **notify_complete** | Marks scan complete if no targets found |
| **Loop Over Items** | Iterates through each endpoint |
| **AI Agent** | GPT-4o-mini analyzes each endpoint for IDOR (baseline → modified request → compare) |
| **fetch_url1** | Tool: AI agent fetches URLs with session cookie for authenticated testing |
| **save_vulnerability** | Tool: AI agent saves confirmed IDOR findings to NileDefender backend |
| **Aggregate** | Collects results after all endpoints are processed |
| **HTTP Request** | Marks scan as complete via `POST /api/scans/:id/complete` |

---

## 🔧 Troubleshooting

```bash
# View NileDefender logs
docker logs niledefender -f

# View n8n logs
docker logs n8n -f

# Rebuild after code changes
docker compose up -d --build

# Check container status
docker compose ps

# Restart a specific service
docker compose restart niledefender
docker compose restart n8n
```

### Common Issues

| Problem | Solution |
|---------|----------|
| n8n shows "Request timed out" in UI | This is a known n8n UI issue. The workflow still runs correctly in the background. Diagnostics and community node fetching are disabled in `docker-compose.yml` to minimize this. |
| Scan stuck in "Running" for 10+ minutes | Safety timeout auto-completes the scan. Check `docker logs n8n -f` to see if the workflow encountered errors. |
| `host.docker.internal` showing in URLs | URLs are automatically normalized. If you see this, restart the NileDefender container: `docker compose restart niledefender` |
| n8n redirects to sign-in instead of sign-up | The n8n instance has already been initialized. Use the credentials you created previously to sign in. |

---

## ⚠️ Important

- The Workflow **must be Active** in n8n before running any scan
- The `config.ini` file is excluded from Git — never commit your real API keys
- If a scan stays **Running** for more than 10 minutes, it will auto-complete (safety timeout)
- Both the AI report generator and n8n IDOR agent use **gpt-4o-mini** — ensure your OpenAI account has API credits
- The `docker-compose.yml` disables n8n diagnostics (`N8N_DIAGNOSTICS_ENABLED=false`) and personalization (`N8N_PERSONALIZATION_ENABLED=false`) for stability
- n8n execution timeouts are set to 600s (max 1200s) in `docker-compose.yml`
