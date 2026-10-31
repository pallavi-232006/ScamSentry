# ScamSentry

> **Detect the Scam. Understand the Threat. Stay Protected.**

ScamSentry is a cybersecurity platform designed to protect individuals and organizations from phishing attacks, deceptive SMS/WhatsApp communications, and malicious URLs using hybrid heuristic indicators and local machine learning classification.

---

## 🛡️ Architecture & Core Modules

1. **Message Threat Scanner**
   - Heuristic and regex-based token analysis of SMS, WhatsApp, and email messages.
   - Identifies credential harvesting (passwords, PINs, SSNs), OTP solicitation, and abnormal payment requests.

2. **Structural URL Inspector**
   - Offline structural analysis of URLs without executing outbound network calls (air-gapped protocol).
   - Detects raw IP hostnames, suspicious TLDs (`.xyz`, `.top`, `.club`), nested subdomains, and lookalike brand impersonation.

3. **Social Engineering Analyzer**
   - Detects psychological persuasion vectors including artificial urgency, fear/intimidation, fake rewards, and authority impersonation.

4. **Intelligent Risk Engine**
   - Computes a normalized risk score from `0` to `100`.
   - Categorizes threats into `LOW` (0–29), `MEDIUM` (30–59), `HIGH` (60–84), and `CRITICAL` (85–100).
   - Provides explainable indicators with score impacts and actionable safety steps.

5. **Local Machine Learning Classifier**
   - Built on Scikit-Learn TF-IDF vectorization and Logistic Regression.
   - Evaluates statistical linguistic markers locally without exposing user text to external third-party APIs.

6. **Audit & Scan History**
   - Persists all threat records into SQLite via SQLAlchemy ORM.
   - Enables users to revisit previous analyses and inspect the full threat breakdown.

---

## 📁 Repository Structure

```
d:\SHINCHAN
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                     # FastAPI application entry & startup seeding
│   │   ├── config.py                   # Pydantic v2 settings & CORS configuration
│   │   ├── database.py                 # SQLite database engine and session factory
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   └── scan_record.py          # SQLAlchemy ScanRecord ORM model
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── scan.py                 # Request and response validation schemas
│   │   │   └── stats.py                # Dashboard analytics schemas
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── router.py               # Aggregated API router
│   │   │   └── v1/
│   │   │       ├── __init__.py
│   │   │       ├── scan.py             # Message & URL scan endpoints
│   │   │       ├── history.py          # SQLite history retrieval & deletion
│   │   │       └── stats.py            # Aggregated metrics for dashboard
│   │   └── core/
│   │       ├── __init__.py
│   │       ├── risk_engine.py          # 0-100 risk score calculator & classifier
│   │       ├── message_scanner.py      # SMS/Email/WhatsApp heuristic analyzer
│   │       ├── url_scanner.py          # Offline structural URL analyzer
│   │       ├── social_engineering.py   # Psychological tactics analyzer
│   │       └── ml_classifier.py        # TF-IDF + Logistic Regression local model
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_health.py              # Health check endpoint tests
│   │   └── test_scanners.py            # Unit tests for URL and message detection
│   ├── requirements.txt                # Python dependencies
│   ├── .env.example
│   └── .env
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   └── layout/
│   │   │       ├── Navbar.jsx          # Header with real-time API status
│   │   │       └── Sidebar.jsx         # Navigation sidebar
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx           # KPI metrics & Recharts analytics
│   │   │   ├── MessageScanner.jsx      # Message analysis view with sample attacks
│   │   │   ├── UrlScanner.jsx          # Safe offline URL inspection view
│   │   │   └── ScanHistory.jsx         # SQLite history view and detail modal
│   │   ├── services/
│   │   │   └── api.js                  # Frontend API client
│   │   ├── App.jsx                     # Top-level view router
│   │   ├── main.jsx                    # React entrypoint
│   │   └── index.css                   # Tailwind and cybersecurity theme styles
│   ├── index.html
│   ├── package.json
│   ├── postcss.config.js
│   ├── tailwind.config.js
│   └── vite.config.js
├── .gitignore
└── README.md
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 2. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1
# (or Windows CMD: .\venv\Scripts\activate.bat)

# Install backend dependencies
pip install -r requirements.txt

# Run backend development server
uvicorn app.main:app --reload --port 8000
```

Backend will be available at:
- **Interactive OpenAPI Documentation**: `http://localhost:8000/docs`
- **Health Check**: `http://localhost:8000/api/health`

### 3. Frontend Setup

```bash
cd frontend

# Install frontend dependencies
npm install

# Start Vite development server
npm run dev
```

Frontend will be available at:
- `http://localhost:5173`

---

## 🧪 Running Automated Tests

To run the backend test suite:

```bash
cd backend
.\venv\Scripts\pytest tests/ -v
```

