import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base

class MonitoredAsset(Base):
    __tablename__ = "monitored_assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_type = Column(String(20), nullable=False)  # 'EMAIL', 'DOMAIN'
    asset_value = Column(String(255), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan_jobs = relationship("ScanJob", back_populates="asset", cascade="all, delete-orphan")
    leak_records = relationship("DarkwebLeakRecord", back_populates="asset", cascade="all, delete-orphan")

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("monitored_assets.id", ondelete="CASCADE"), nullable=False)
    job_type = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, default="PENDING")  # PENDING, PROCESSING, COMPLETED, FAILED
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    asset = relationship("MonitoredAsset", back_populates="scan_jobs")

class DarkwebLeakRecord(Base):
    __tablename__ = "darkweb_leak_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("monitored_assets.id", ondelete="CASCADE"), nullable=False)
    source_type = Column(String(50), nullable=False)  # 'HOLEHE', 'DARKWEB_CRAWLER', 'STEALER_LOG'
    breach_title = Column(String(150), nullable=False)
    raw_data = Column(Text, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("MonitoredAsset", back_populates="leak_records")