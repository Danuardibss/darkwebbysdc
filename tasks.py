import os
import uuid
import asyncio
from celery import Celery
from datetime import datetime
from database import SessionLocal
from models import (
    ScanJob, 
    DarkwebLeakRecord, 
    PIIExposure, 
    StealerLog, 
    PIIType, 
    RiskLevel
)

# Impor pipeline pemindaian eksis
from main import run_scan_pipeline

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
celery_app = Celery("darkweb_tasks", broker=REDIS_URL, backend=REDIS_URL)

def calculate_risk(pii_type: PIIType, has_cookies: bool = False) -> RiskLevel:
    """Menghitung tingkat risiko kebocoran data secara otomatis."""
    if pii_type == PIIType.SESSION_COOKIE or (pii_type == PIIType.PASSWORD_PLAIN and has_cookies):
        return RiskLevel.CRITICAL
    elif pii_type == PIIType.PASSWORD_PLAIN:
        return RiskLevel.HIGH
    elif pii_type in [PIIType.PASSWORD_HASH, PIIType.IP_ADDRESS]:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW

@celery_app.task(bind=True)
def execute_darkweb_scan_job(self, job_id: str, target: str, asset_id: str):
    db = SessionLocal()
    try:
        # Konversi ID string ke objek UUID
        job_uuid = uuid.UUID(job_id) if isinstance(job_id, str) else job_id
        asset_uuid = uuid.UUID(asset_id) if isinstance(asset_id, str) else asset_id

        # 1. Update status ke PROCESSING
        job = db.query(ScanJob).filter(ScanJob.id == job_uuid).first()
        if job:
            job.status = "PROCESSING"
            db.commit()

        # 2. Jalankan pipeline pemindaian eksis (holehe, crawler, dll)
        scan_results = asyncio.run(run_scan_pipeline(target))

        # 3. Simpan Record Leak Mentah (History Utama)
        leak_entry = DarkwebLeakRecord(
            asset_id=asset_uuid,
            source_type="DARKWEB_SWEEP",
            breach_title=f"Scan result for {target}",
            raw_data=str(scan_results)
        )
        db.add(leak_entry)

        # 4. Parsing Hasil ke PII Exposure & Stealer Logs
        if isinstance(scan_results, dict):
            # Parsing Stealer Logs jika ditemukan
            stealer_findings = scan_results.get("stealer_logs", [])
            for log in stealer_findings:
                stealer_entry = StealerLog(
                    asset_id=asset_uuid,
                    job_id=job_uuid,
                    malware_name=log.get("malware_name", "Unknown Stealer"),
                    infected_host=log.get("infected_host"),
                    infected_url=log.get("infected_url"),
                    has_cookies=log.get("has_cookies", False),
                    raw_log=str(log)
                )
                db.add(stealer_entry)

            # Parsing PII Exposures jika ditemukan
            pii_findings = scan_results.get("pii_exposures", [])
            for pii in pii_findings:
                p_type = pii.get("type", PIIType.EMAIL)
                p_val = pii.get("value", target)
                has_cookie = pii.get("has_cookies", False)
                
                risk = calculate_risk(p_type, has_cookies=has_cookie)

                pii_entry = PIIExposure(
                    asset_id=asset_uuid,
                    job_id=job_uuid,
                    pii_type=p_type,
                    raw_value=p_val,
                    risk_level=risk,
                    source=pii.get("source", "Darkweb Breach Engine")
                )
                db.add(pii_entry)

        # 5. Update Status Job ke COMPLETED
        if job:
            job.status = "COMPLETED"
            job.completed_at = datetime.utcnow()
            db.commit()

    except Exception as e:
        db.rollback()
        job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(job_id) if isinstance(job_id, str) else job_id).first()
        if job:
            job.status = "FAILED"
            job.error_message = str(e)
            db.commit()
        raise e
    finally:
        db.close()