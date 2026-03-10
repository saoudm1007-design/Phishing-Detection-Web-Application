# PhishRadar — Phishing Detection Web Application

An advanced phishing detection web application combining heuristic analysis, Google Safe Browsing API, and VirusTotal API to detect malicious URLs, IP addresses, domains, and file hashes. Supports Arabic/English with full RTL layout.

## Live Demo

🌐 [phishing.saoud.site](https://phishing.saoud.site)

## Features

- **URL Scanner** — 3-layer detection with live progress indicator
  - Heuristic analysis (15+ signals, instant)
  - Google Safe Browsing API (~1 second)
  - VirusTotal API — 70+ antivirus engines (~15 seconds)
- **IP Address Lookup** — Country, ASN, owner, engine verdicts
- **Domain Reputation** — Registrar, age, categories, engine verdicts
- **File Hash Lookup** — MD5 / SHA1 / SHA256 against 76+ engines
- **WHOIS Domain Age** — Flags newly registered domains
- **Risk Scoring** — 0–100 score with LIKELY SAFE / SUSPICIOUS / PHISHING verdict
- **Shareable Results** — Unique link generated per scan (stored in SQLite)
- **Dark / Light Mode** — Theme toggle with saved preference
- **Arabic / English** — Full RTL/LTR bilingual support
- **How It Works** — Dedicated guide page explaining all detection layers

## Tech Stack

- **Backend** — Python, Flask, Gunicorn
- **Frontend** — HTML, CSS, JavaScript (no frameworks)
- **Database** — SQLite (scan result sharing)
- **APIs** — VirusTotal API v3, Google Safe Browsing API v4
- **Libraries** — tldextract, python-whois, python-dotenv, requests

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/saoudm1007-design/Phishing-Detection-Web-Application.git
cd Phishing-Detection-Web-Application
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install flask gunicorn requests tldextract scikit-learn numpy python-whois python-dotenv
```

### 4. Configure API keys

```bash
cp .env.example .env
```

Edit `.env` and add your keys:

```
VT_API_KEY=your_virustotal_api_key_here
GOOGLE_SB_KEY=your_google_safe_browsing_api_key_here
```

- **VirusTotal** — Free API key at [virustotal.com](https://www.virustotal.com) (500 requests/day)
- **Google Safe Browsing** — Free API key via [Google Cloud Console](https://console.cloud.google.com) (10,000 requests/day)

### 5. Run the application

```bash
python3 app.py
```

Or with Gunicorn (production):

```bash
gunicorn --worker-class gthread --workers 1 --threads 4 --bind 0.0.0.0:5000 app:app
```

App runs at `http://localhost:5000`

## Nginx Deployment (Production)

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location /analyze {
        limit_req zone=phishradar burst=5 nodelay;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_read_timeout 60s;
    }

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Project Structure

```
├── app.py                  # Flask backend — detection logic & API routes
├── templates/
│   └── index.html          # Frontend — UI, tabs, progress, results
├── static/
│   └── favicon.svg
├── .env.example            # API key template (copy to .env)
├── .gitignore
└── README.md
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/analyze/quick` | Heuristics + WHOIS + Google Safe Browsing |
| POST | `/analyze/vt` | VirusTotal scan |
| POST | `/lookup/ip` | IP address reputation |
| POST | `/lookup/domain` | Domain reputation |
| POST | `/lookup/hash` | File hash lookup |
| GET | `/result/<id>` | Shared scan result |
| GET | `/health` | Health check |

## Detection Signals (Heuristics)

| Signal | Risk Weight |
|--------|-------------|
| IP address used as domain | +30 |
| No HTTPS | +15 |
| Suspicious TLD (.xyz, .tk...) | +25 |
| Brand impersonation | +35 |
| Google Safe Browsing hit | +40 |
| VirusTotal malicious engines | +5 per engine (max +30) |
| New domain (< 30 days) | +20 |
| Suspicious keywords | +10 / +25 |
| High URL entropy | +15 |
| Encoded characters | +10 |

## License

MIT
