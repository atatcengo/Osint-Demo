# Passive OSINT Demo

A beginner-friendly passive OSINT web app for educational purposes. Enter a domain name and get a clean security-footprint summary using only public, passive data sources.

## What it does

- **Subdomain discovery** via certificate transparency logs (crt.sh)
- **DNS record lookup** — A, MX, TXT, and NS records
- **Shodan integration** — open ports, org, ISP, country, and CVEs per IP (optional, requires API key)
- **VirusTotal integration** — harmless/suspicious/malicious reputation counts (optional, requires API key)
- **Scan history** — automatically saves every scan so you can reload and compare past results
- **Markdown report export** — download a formatted report of any scan

> No active scanning, brute forcing, directory traversal, login testing, or exploitation is performed. This tool is for educational OSINT reporting only.

## Example domain to demo

Try: `biga.bel.tr`

---

## Running locally

### Prerequisites

- [Node.js](https://nodejs.org/) v18 or higher
- [pnpm](https://pnpm.io/) v9 or higher (`npm install -g pnpm`)
- A PostgreSQL database (local or hosted — e.g. [Neon](https://neon.tech/), [Supabase](https://supabase.com/))

### 1. Clone the project

Download your project from Replit (use the three-dot menu → Download as zip), then unzip it.

### 2. Install dependencies

```bash
pnpm install
```

### 3. Set environment variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

Edit `.env`:

```env
# Required — your PostgreSQL connection string
DATABASE_URL=postgresql://user:password@localhost:5432/osint_demo

# Optional — add your Shodan API key from https://account.shodan.io/
SHODAN_API_KEY=your_shodan_key_here

# Optional — add your VirusTotal API key from https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

### 4. Set up the database

```bash
pnpm --filter @workspace/db run push
```

### 5. Start the API server

Open a terminal and run:

```bash
PORT=8080 BASE_PATH=/api pnpm --filter @workspace/api-server run dev
```

### 6. Start the frontend

Open a second terminal and run:

```bash
PORT=3000 BASE_PATH=/ pnpm --filter @workspace/osint-demo run dev
```

Then open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Adding API keys in Replit

If you're running on Replit, add secrets in the **Secrets** tab (the lock icon in the left sidebar):

| Secret name | Where to get it |
|---|---|
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io/) |
| `VIRUSTOTAL_API_KEY` | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |

The app works without these keys — Shodan and VirusTotal sections will show "Not configured."

---

## Project structure

```
artifacts/
  api-server/     — Express API server (OSINT logic, scan history endpoints)
  osint-demo/     — React + Vite frontend
lib/
  api-spec/       — OpenAPI spec (source of truth for all API contracts)
  api-client-react/ — Generated React Query hooks (from OpenAPI)
  api-zod/        — Generated Zod validation schemas (from OpenAPI)
  db/             — PostgreSQL schema + Drizzle ORM
```

---

## Ethical limitations

- Only passive, public data sources are used
- No login testing, brute forcing, or active port scanning
- No exploitation of any kind
- Intended for academic and educational demonstrations only
- Always get permission before scanning domains you don't own
