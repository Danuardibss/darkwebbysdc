import os
import asyncio
from celery import Celery
from datetime import datetime
from database import SessionLocal
from models import ScanJob, DarkwebLeakRecord

# Impor pipeline pemindaian eksis yang kamu punya
from main import run_scan_pipeline

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
celery_app = Celery("darkweb_tasks", broker=REDIS_URL, backend=REDIS_URL)

@celery_app.task(bind=True)
def execute_darkweb_scan_job(self, job_id: str, target: str, asset_id: str):
    db = SessionLocal()
    try:
        # Update status ke PROCESSING
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if job:
            job.status = "PROCESSING"
            db.commit()

        # Jalankan pipeline pemindaian eksis (holehe, darkweb_crawler, dll)
        scan_results = asyncio.run(run_scan_pipeline(target))

        # Simpan hasil pemindaian ke database
        leak_entry = DarkwebLeakRecord(
            asset_id=asset_id,
            source_type="DARKWEB_SWEEP",
            breach_title=f"Scan result for {target}",
            raw_data=str(scan_results)
        )
        db.add(leak_entry)

        if job:
            job.status = "COMPLETED"
            job.completed_at = datetime.utcnow()
            db.commit()

    except Exception as e:
        if job:
            job.status = "FAILED"
            job.error_message = str(e)
            db.commit()
    finally:
        db.close()