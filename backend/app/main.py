from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.api.router import api_router
from app.models.scan_record import ScanRecord


def seed_sample_data():
    """Seed sample data on first run if database is empty."""
    db = SessionLocal()
    try:
        count = db.query(ScanRecord).count()
        if count == 0:
            sample_records = [
                ScanRecord(
                    scan_type="message",
                    target_summary="URGENT: Your Wells Fargo account is locked. Verify now at...",
                    raw_content="URGENT: Your Wells Fargo account is locked due to unauthorized charges. Verify your identity within 24 hours at http://wellsfargo-secure-login.xyz to restore access.",
                    risk_score=92.5,
                    threat_level="CRITICAL",
                    category="Credential Theft",
                    created_at=datetime.now(timezone.utc),
                ),
                ScanRecord(
                    scan_type="url",
                    target_summary="http://192.168.1.105:8080/paypal-update/auth",
                    raw_content="http://192.168.1.105:8080/paypal-update/auth",
                    risk_score=85.0,
                    threat_level="CRITICAL",
                    category="URL Deception",
                    created_at=datetime.now(timezone.utc),
                ),
                ScanRecord(
                    scan_type="message",
                    target_summary="Hey, are we still meeting for lunch today at 12:30?",
                    raw_content="Hey, are we still meeting for lunch today at 12:30? Let me know if that works for you.",
                    risk_score=0.0,
                    threat_level="LOW",
                    category="Safe / Legitimate",
                    created_at=datetime.now(timezone.utc),
                ),
                ScanRecord(
                    scan_type="message",
                    target_summary="Congratulations! You have won $5,000 Walmart Gift Card. Claim now...",
                    raw_content="Congratulations! You have won a $5,000 Walmart Gift Card in our holiday sweepstakes. Click to claim your prize: http://bit.ly/walmart-free-gift",
                    risk_score=68.0,
                    threat_level="HIGH",
                    category="Greed / Reward",
                    created_at=datetime.now(timezone.utc),
                ),
            ]
            
            sample_records[0].indicators = [
                {"name": "Artificial Urgency Trigger", "category": "Urgency", "severity": "high", "score_impact": 30.0, "description": "Demands action within 24 hours."},
                {"name": "High-Risk Top-Level Domain", "category": "URL Deception", "severity": "warning", "score_impact": 20.0, "description": "Domain ends with .xyz"},
                {"name": "Brand Lookalike (Wellsfargo)", "category": "Impersonation", "severity": "critical", "score_impact": 50.0, "description": "Unauthorized use of brand in unofficial domain."}
            ]
            sample_records[0].phrases = ["within 24 hours", "locked", ".xyz", "wellsfargo"]
            sample_records[0].recommendations = ["Do NOT click the link.", "Never provide account credentials via SMS."]

            sample_records[1].indicators = [
                {"name": "IP Address Hostname", "category": "URL Deception", "severity": "critical", "score_impact": 60.0, "description": "Points directly to an IP address."},
                {"name": "Non-Standard Port", "category": "URL Deception", "severity": "warning", "score_impact": 25.0, "description": "Communicates over port 8080."}
            ]
            sample_records[1].phrases = ["192.168.1.105", ":8080", "paypal"]
            sample_records[1].recommendations = ["Never enter credentials on numeric IP addresses."]

            sample_records[2].indicators = []
            sample_records[2].phrases = []
            sample_records[2].recommendations = ["No suspicious indicators found."]

            sample_records[3].indicators = [
                {"name": "Fake Financial Rewards / Lottery", "category": "Greed / Reward", "severity": "high", "score_impact": 35.0, "description": "Unsolicited gift card prize claim."},
                {"name": "URL Shortening Service", "category": "Shortener", "severity": "warning", "score_impact": 25.0, "description": "Uses bit.ly to obscure target URL."}
            ]
            sample_records[3].phrases = ["congratulations", "gift card", "bit.ly"]
            sample_records[3].recommendations = ["Ignore unsolicited prize alerts."]

            db.add_all(sample_records)
            db.commit()
    except Exception as e:
        print(f"Sample data seeding error: {e}")
        db.rollback()
    finally:
        db.close()


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
