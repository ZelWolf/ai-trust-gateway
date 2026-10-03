import os
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timezone

DB_DIR = "./data"
os.makedirs(DB_DIR, exist_ok=True)
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_DIR}/sentinel_audit.db"

# check_same_thread=False is required for FastAPI to use SQLite safely across async requests
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String, unique=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    decision = Column(String)       # BLOCK, REDACT, ALLOW
    risk_level = Column(String)     # CRITICAL, HIGH, MEDIUM, LOW
    intent = Column(String)
    policy_id = Column(String, nullable=True)
    reason = Column(String)
    l1_ms = Column(Float)
    l2_ms = Column(Float)
    total_ms = Column(Float)

# Create the table on startup
Base.metadata.create_all(bind=engine)

def get_db():
    """Dependency to yield a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()