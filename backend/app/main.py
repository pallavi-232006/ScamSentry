from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.api.router import api_router
from app.models.scan_record import ScanRecord


def seed_sample_data():
    """
    Seed demonstration records on first run (empty database only).
    These records are clearly labeled demo data and represent a realistic
    spread of scan types, risk levels, and categories across the past 7 days.
    No record is inserted if the database already contains any rows.
    """
    db = SessionLocal()
    try:
        if db.query(ScanRecord).count() > 0:
            return  # Do not seed if real scans already exist

        now = datetime.now(timezone.utc)

        # Helper: offset timestamp by N days ago
        def days_ago(n, hour=10, minute=0):
            return (now - timedelta(days=n)).replace(hour=hour, minute=minute, second=0, microsecond=0)

        sample_records = [
            # ── Day 6 ago ──────────────────────────────────────────────────────
            ScanRecord(
                scan_type="message",
                target_summary="[Demo] URGENT: Your Wells Fargo account is locked. Verify now at...",
                raw_content="[Demo] URGENT: Your Wells Fargo account is locked due to unauthorized charges. Verify your identity within 24 hours at http://wellsfargo-secure-login.xyz to restore access.",
                risk_score=92.5,
                threat_level="CRITICAL",
                category="Credential Theft",
                created_at=days_ago(6, hour=9),
            ),
            ScanRecord(
                scan_type="url",
                target_summary="[Demo] http://192.168.1.105:8080/paypal-update/auth",
                raw_content="http://192.168.1.105:8080/paypal-update/auth",
                risk_score=85.0,
                threat_level="CRITICAL",
                category="URL Deception",
                created_at=days_ago(6, hour=14),
            ),
            # ── Day 5 ago ──────────────────────────────────────────────────────
            ScanRecord(
                scan_type="message",
                target_summary="[Demo] Hey, are we still meeting for lunch today at 12:30?",
                raw_content="[Demo] Hey, are we still meeting for lunch today at 12:30? Let me know if that works for you.",
                risk_score=0.0,
                threat_level="LOW",
                category="Safe / Legitimate",
                created_at=days_ago(5, hour=11),
            ),
            ScanRecord(
                scan_type="message",
                target_summary="[Demo] Congratulations! You have won $5,000 Walmart Gift Card...",
                raw_content="[Demo] Congratulations! You have won a $5,000 Walmart Gift Card in our holiday sweepstakes. Click to claim your prize: http://bit.ly/walmart-free-gift",
                risk_score=68.0,
                threat_level="HIGH",
                category="Lottery / Prize",
                created_at=days_ago(5, hour=15),
            ),
            # ── Day 4 ago ──────────────────────────────────────────────────────
            ScanRecord(
                scan_type="message",
                target_summary="[Demo] PhonePe Reward: Enter your UPI PIN to claim Rs 25,000...",
                raw_content="[Demo] PhonePe Reward: You have received a cash reward of Rs 25,000! Enter your secret UPI PIN to claim money instantly into your bank account.",
                risk_score=88.0,
                threat_level="CRITICAL",
                category="UPI Fraud",
                created_at=days_ago(4, hour=10),
            ),
            ScanRecord(
                scan_type="url",
                target_summary="[Demo] https://www.google.com/search?q=python+tutorial",
                raw_content="https://www.google.com/search?q=python+tutorial",
                risk_score=5.0,
                threat_level="LOW",
                category="Safe / Legitimate",
                created_at=days_ago(4, hour=13),
            ),
            # ── Day 3 ago ──────────────────────────────────────────────────────
            ScanRecord(
                scan_type="message",
                target_summary="[Demo] CBI & Cyber Crime Cell: Digital Arrest. Transfer Rs 2,50,000...",
                raw_content="[Demo] CBI & Cyber Crime Cell Notice: A courier package containing narcotics in your name was intercepted. You are under Digital Arrest. Transfer Rs 2,50,000 to RBI escrow to clear charges.",
                risk_score=97.0,
                threat_level="CRITICAL",
                category="Government Impersonation",
                created_at=days_ago(3, hour=9),
            ),
            ScanRecord(
                scan_type="message",
                target_summary="[Demo] Your Amazon order #112-9281 has been shipped...",
                raw_content="[Demo] Your Amazon order #112-9281 has been shipped and will arrive by Thursday. Track your package at amazon.in/orders.",
                risk_score=3.0,
                threat_level="LOW",
                category="Safe / Legitimate",
                created_at=days_ago(3, hour=16),
            ),
            # ── Day 2 ago ──────────────────────────────────────────────────────
            ScanRecord(
                scan_type="message",
                target_summary="[Demo] Dear SBI user, your YONO account is blocked — KYC update...",
                raw_content="[Demo] Dear SBI user, your YONO account is blocked today due to pending KYC update. Click http://sbi-kyc-pan-update.xyz to update PAN and Aadhaar immediately.",
                risk_score=82.0,
                threat_level="CRITICAL",
                category="Bank Impersonation",
                created_at=days_ago(2, hour=8),
            ),
            ScanRecord(
                scan_type="url",
                target_summary="[Demo] http://sbi-kyc-pan-update.xyz/verify",
                raw_content="http://sbi-kyc-pan-update.xyz/verify",
                risk_score=55.0,
                threat_level="HIGH",
                category="URL Deception",
                created_at=days_ago(2, hour=8),
            ),
            ScanRecord(
                scan_type="message",
                target_summary="[Demo] Work From Home Internship! Earn Rs 2,500 daily — pay Rs 499 fee...",
                raw_content="[Demo] Work From Home Internship at TCS! Earn Rs 2,500 daily for data entry. Pay Rs 499 refundable equipment fee via UPI to start. Contact HR on Telegram @remote_career_now.",
                risk_score=47.0,
                threat_level="MEDIUM",
                category="Employment Fraud",
                created_at=days_ago(2, hour=17),
            ),
            # ── Yesterday ──────────────────────────────────────────────────────
            ScanRecord(
                scan_type="message",
                target_summary="[Demo] PM Kisan Samman Nidhi: DBT subsidy of Rs 6,000 approved...",
                raw_content="[Demo] PM Kisan Samman Nidhi: Your DBT subsidy of Rs 6,000 has been approved. Click to verify your Aadhaar and bank details at http://pmkisan-dbt-subsidy.top",
                risk_score=78.0,
                threat_level="CRITICAL",
                category="Government Impersonation",
                created_at=days_ago(1, hour=10),
            ),
            ScanRecord(
                scan_type="message",
                target_summary="[Demo] Reminder: your dentist appointment is at 3 PM tomorrow.",
                raw_content="[Demo] Reminder: your dentist appointment is at 3 PM tomorrow. Reply CONFIRM or call 98765-43210 to reschedule.",
                risk_score=2.0,
                threat_level="LOW",
                category="Safe / Legitimate",
                created_at=days_ago(1, hour=14),
            ),
            ScanRecord(
                scan_type="url",
                target_summary="[Demo] https://bit.ly/claim-free-iphone15",
                raw_content="https://bit.ly/claim-free-iphone15",
                risk_score=42.0,
                threat_level="MEDIUM",
                category="URL Deception",
                created_at=days_ago(1, hour=19),
            ),
            # ── Today ──────────────────────────────────────────────────────────
            ScanRecord(
                scan_type="message",
                target_summary="[Demo] India Post: Consignment failed delivery. Pay Rs 25 redelivery...",
                raw_content="[Demo] India Post Notice: Consignment #IN82019 failed delivery. Pay Rs 25 redelivery charge at http://indiapost-parcel-redelivery.xyz to avoid return.",
                risk_score=63.0,
                threat_level="HIGH",
                category="Package Phishing",
                created_at=days_ago(0, hour=9),
            ),
        ]

        # Attach minimal indicator / phrase / recommendation data
        _seed_metadata(sample_records)

        db.add_all(sample_records)
        db.commit()
        print(f"[ScamSentry] Seeded {len(sample_records)} demo records into empty database.")
    except Exception as e:
        print(f"[ScamSentry] Sample data seeding error: {e}")
        db.rollback()
    finally:
        db.close()


def _seed_metadata(records: list):
    """Attach indicator / phrase / recommendation JSON to each seed record."""
    import json

    meta = {
        0: {  # Wells Fargo CRITICAL
            "indicators": [
                {"name": "Artificial Urgency Trigger", "category": "Urgency", "severity": "high", "score_impact": 30.0, "description": "Demands action within 24 hours."},
                {"name": "Brand Lookalike Domain", "category": "Impersonation", "severity": "critical", "score_impact": 50.0, "description": "Unauthorized brand use in unofficial .xyz domain."},
            ],
            "phrases": ["within 24 hours", "locked", ".xyz", "wellsfargo"],
            "recommendations": ["Do NOT click the link.", "Never provide credentials over SMS."],
        },
        1: {  # IP URL CRITICAL
            "indicators": [
                {"name": "IP Address Hostname", "category": "URL Deception", "severity": "critical", "score_impact": 60.0, "description": "Points directly to an IP address."},
                {"name": "Non-Standard Port", "category": "URL Deception", "severity": "warning", "score_impact": 25.0, "description": "Communicates over port 8080."},
            ],
            "phrases": ["192.168.1.105", ":8080", "paypal"],
            "recommendations": ["Never enter credentials on numeric IP addresses."],
        },
        2: {  # Lunch LOW
            "indicators": [],
            "phrases": [],
            "recommendations": ["No suspicious indicators detected."],
        },
        3: {  # Gift card HIGH
            "indicators": [
                {"name": "Fake Financial Reward", "category": "Lottery / Prize", "severity": "high", "score_impact": 35.0, "description": "Unsolicited gift card prize claim."},
                {"name": "URL Shortening Service", "category": "Shortener", "severity": "warning", "score_impact": 25.0, "description": "Uses bit.ly to obscure target URL."},
            ],
            "phrases": ["congratulations", "gift card", "bit.ly"],
            "recommendations": ["Ignore unsolicited prize alerts."],
        },
        4: {  # UPI PIN CRITICAL
            "indicators": [
                {"name": "Fraudulent UPI PIN Solicitation", "category": "UPI Fraud", "severity": "critical", "score_impact": 50.0, "description": "UPI PIN is only needed to SEND money, never to receive."},
            ],
            "phrases": ["upi pin", "claim money instantly"],
            "recommendations": ["UPI PIN is for sending only. Never enter it to receive money."],
        },
        5: {  # Google LOW
            "indicators": [],
            "phrases": [],
            "recommendations": ["No suspicious indicators detected."],
        },
        6: {  # Digital Arrest CRITICAL
            "indicators": [
                {"name": "Digital Arrest Cyber Extortion", "category": "Government Impersonation", "severity": "critical", "score_impact": 50.0, "description": "CBI/Police Digital Arrest extortion scheme."},
            ],
            "phrases": ["digital arrest", "cbi", "narcotics", "transfer"],
            "recommendations": ["Real law enforcement does NOT conduct arrests over phone/video call.", "Hang up immediately and call 1930 (Cyber Crime Helpline)."],
        },
        7: {  # Amazon LOW
            "indicators": [],
            "phrases": [],
            "recommendations": ["No suspicious indicators detected."],
        },
        8: {  # SBI KYC CRITICAL
            "indicators": [
                {"name": "Indian Banking KYC Suspension Scam", "category": "Bank Impersonation", "severity": "critical", "score_impact": 48.0, "description": "Phishing impersonating SBI threatening account deactivation."},
            ],
            "phrases": ["kyc update", "sbi", "blocked", "pan", "aadhaar"],
            "recommendations": ["Visit the official bank branch for KYC updates.", "Never click links in SMS for KYC."],
        },
        9: {  # sbi-kyc URL HIGH
            "indicators": [
                {"name": "Brand Impersonation in Domain", "category": "URL Deception", "severity": "high", "score_impact": 40.0, "description": "Domain spoofs SBI brand using hyphenated subdomain."},
                {"name": "High-Risk TLD", "category": "URL Deception", "severity": "warning", "score_impact": 15.0, "description": "Uses .xyz TLD commonly abused in phishing."},
            ],
            "phrases": ["sbi-kyc-pan-update.xyz"],
            "recommendations": ["SBI official domains end in sbi.co.in only."],
        },
        10: {  # WFH Internship MEDIUM
            "indicators": [
                {"name": "High-Yield Work-From-Home Scam", "category": "Employment Fraud", "severity": "high", "score_impact": 38.0, "description": "Promises unrealistic pay for minimal work."},
                {"name": "Unorthodox Recruitment Funnel", "category": "Employment Fraud", "severity": "high", "score_impact": 35.0, "description": "Directs applicants to Telegram and demands advance fee."},
            ],
            "phrases": ["work from home", "rs 2,500 daily", "refundable", "telegram"],
            "recommendations": ["Legitimate employers never charge fees before joining.", "Avoid Telegram-only recruitment channels."],
        },
        11: {  # PM Kisan CRITICAL
            "indicators": [
                {"name": "Indian Government DBT Welfare Fraud", "category": "Government Impersonation", "severity": "critical", "score_impact": 42.0, "description": "Fabricated PM Kisan DBT scheme to harvest banking credentials."},
            ],
            "phrases": ["pm kisan", "dbt subsidy", "aadhaar", "bank details"],
            "recommendations": ["PM Kisan payments are automatic — no link-clicking required.", "Visit pmkisan.gov.in directly."],
        },
        12: {  # Dentist LOW
            "indicators": [],
            "phrases": [],
            "recommendations": ["No suspicious indicators detected."],
        },
        13: {  # bit.ly MEDIUM
            "indicators": [
                {"name": "URL Shortening Service", "category": "Shortener", "severity": "warning", "score_impact": 25.0, "description": "Uses bit.ly to obscure true destination."},
                {"name": "Suspicious Keywords in Path", "category": "URL Deception", "severity": "warning", "score_impact": 17.0, "description": "Path contains 'free' and brand name suggesting phishing bait."},
            ],
            "phrases": ["bit.ly", "free", "iphone"],
            "recommendations": ["Expand shortened URLs before clicking using tools like checkshorturl.com."],
        },
        14: {  # India Post HIGH
            "indicators": [
                {"name": "Indian Postal & Courier Delivery Phishing", "category": "Package Phishing", "severity": "high", "score_impact": 38.0, "description": "Impersonates India Post demanding nominal redelivery fee."},
            ],
            "phrases": ["india post", "redelivery charge", "rs 25"],
            "recommendations": ["India Post does NOT collect redelivery fees via SMS links.", "Visit indiapost.gov.in directly."],
        },
    }

    for idx, record in enumerate(records):
        m = meta.get(idx, {"indicators": [], "phrases": [], "recommendations": []})
        record.indicators = m["indicators"]
        record.phrases = m["phrases"]
        record.recommendations = m["recommendations"]


# Ensure database tables exist
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    seed_sample_data()
    yield
    # Shutdown logic if any


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Intelligent Cybersecurity Platform for Scam & Threat Detection",
    lifespan=lifespan,
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Hackathon dev mode allows all local origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/api/health", tags=["Health"])
def health_check():
    """Health check endpoint to verify backend operational readiness."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/", tags=["Root"])
def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "docs_url": "/docs",
        "health_url": "/api/health",
        "version": settings.VERSION,
    }
