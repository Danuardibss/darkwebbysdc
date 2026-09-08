import uuid
import enum
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base

class RiskLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class PIIType(str, enum.Enum):
    EMAIL = "EMAIL"
    PASSWORD_PLAIN = "PASSWORD_PLAIN"
    PASSWORD_HASH = "PASSWORD_HASH"
    SESSION_COOKIE = "SESSION_COOKIE"
    IP_ADDRESS = "IP_ADDRESS"
    PHONE = "PHONE"

class MonitoredAsset(Base):
    __tablename__ = "monitored_assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_type = Column(String(20), nullable=False)  # 'EMAIL', 'DOMAIN', 'USERNAME'
    asset_value = Column(String(255), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan_jobs = relationship("ScanJob", back_populates="asset", cascade="all, delete-orphan")
    leak_records = relationship("DarkwebLeakRecord", back_populates="asset", cascade="all, delete-orphan")
    pii_exposures = relationship("PIIExposure", back_populates="asset", cascade="all, delete-orphan")
    stealer_logs = relationship("StealerLog", back_populates="asset", cascade="all, delete-orphan")

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("monitored_assets.id", ondelete="CASCADE"), nullable=False)
    job_type = Column(String(50), nullable=False, default="FULL_DARKWEB_SCAN")
    status = Column(String(20), nullable=False, default="PENDING")  # PENDING, PROCESSING, COMPLETED, FAILED
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    asset = relationship("MonitoredAsset", back_populates="scan_jobs")
    pii_exposures = relationship("PIIExposure", back_populates="job", cascade="all, delete-orphan")
    stealer_logs = relationship("StealerLog", back_populates="job", cascade="all, delete-orphan")

class DarkwebLeakRecord(Base):
    __tablename__ = "darkweb_leak_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("monitored_assets.id", ondelete="CASCADE"), nullable=False)
    source_type = Column(String(50), nullable=False)  # 'HOLEHE', 'DARKWEB_CRAWLER', 'PASTE_SITE'
    breach_title = Column(String(150), nullable=False)
    raw_data = Column(Text, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("MonitoredAsset", back_populates="leak_records")

class PIIExposure(Base):
    __tablename__ = "pii_exposures"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("monitored_assets.id", ondelete="CASCADE"), nullable=False)
    job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=True)
    pii_type = Column(SQLEnum(PIIType), nullable=False)
    raw_value = Column(String(255), nullable=False)
    risk_level = Column(SQLEnum(RiskLevel), nullable=False, default=RiskLevel.LOW)
    source = Column(String(100), nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("MonitoredAsset", back_populates="pii_exposures")
    job = relationship("ScanJob", back_populates="pii_exposures")

class StealerLog(Base):
    __tablename__ = "stealer_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("monitored_assets.id", ondelete="CASCADE"), nullable=False)
    job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=True)
    malware_name = Column(String(100), nullable=True)  # RedLine, Lumma, Vidar, Raccoon
    infected_host = Column(String(100), nullable=True)
    infected_url = Column(Text, nullable=True)
    has_cookies = Column(Boolean, default=False)
    raw_log = Column(Text, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("MonitoredAsset", back_populates="stealer_logs")
    job = relationship("ScanJob", back_populates="stealer_logs")