import subprocess
import json
import os
import shutil
import asyncio
import concurrent.futures
import requests
import argparse
import uuid
from bs4 import BeautifulSoup
from datetime import datetime
from fastapi import FastAPI, Query, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

# Import koneksi Database & Model ORM Terbaru
from database import engine, Base, get_db
from models import (
    MonitoredAsset, 
    ScanJob, 
    DarkwebLeakRecord, 
    PIIExposure, 
    StealerLog, 
    RiskLevel, 
    PIIType
)

# Inisialisasi Tabel Database
Base.metadata.create_all(bind=engine)

# ==========================================
# IMPORT VALIDATOR (WITH FALLBACK)
# ==========================================
try:
    from validator import check_cpanel, check_ftp, check_basic_auth
except ImportError:
    def check_cpanel(url, user, pwd):
        return {"status": "ERROR", "message": "Fungsi check_cpanel tidak ditemukan di validator.py"}
    def check_ftp(url, user, pwd):
        return {"status": "ERROR", "message": "Fungsi check_ftp tidak ditemukan di validator.py"}
    def check_basic_auth(url, user, pwd):
        return {"status": "ERROR", "message": "Fungsi check_basic_auth tidak ditemukan di validator.py"}

check_cpanel_login = check_cpanel


# ==========================================
# 1. CORE OSINT & BREACH FUNCTIONS
# ==========================================
def search_darkweb_ahmia(query):
    url = f"https://ahmia.fi/search/?q={query}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            results = []
            for li in soup.find_all('li', class_='result'):
                title_elem = li.find('a')
                snippet_elem = li.find('p')
                cite_elem = li.find('cite')
                
                if title_elem and cite_elem:
                    results.append({
                        "title": title_elem.text.strip(),
                        "onion_url": cite_elem.text.strip(),
                        "snippet": snippet_elem.text.strip() if snippet_elem else "No description"
                    })
            return {"status": "SUCCESS", "total_found": len(results), "matches": results}
        return {"status": "CLEAN", "total_found": 0, "matches": []}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

def check_stealer_log_sync(email):
    url = f"https://cavalier.hudsonrock.com/api/v1/osint-tools/search-by-email?email={email}"
    try:
        res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=8)
        if res.status_code == 200:
            data = res.json()
            return {
                "status": "COMPROMISED" if data.get("stealer_logs_count", 0) > 0 else "CLEAN",
                "stealer_logs_count": data.get("stealer_logs_count", 0),
                "compromised_passwords": data.get("passwords_count", 0),
                "raw_data": data
            }
        return {"status": "CLEAN", "stealer_logs_count": 0, "compromised_passwords": 0}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

def check_public_breaches_sync(email):
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=8)
        if res.status_code == 200:
            data = res.json()
            if "breaches" in data:
                breaches = data["breaches"]
                detailed = breaches[0] if isinstance(breaches, list) and len(breaches) > 0 else breaches
                return {"status": "BREACHED", "total_breaches": len(detailed) if isinstance(detailed, list) else 1, "exposed_in": detailed}
        return {"status": "CLEAN", "total_breaches": 0, "exposed_in": []}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

def check_holehe_sync(email):
    try:
        bat_path = os.path.join(os.getcwd(), "holehe.bat")
        holehe_exe = bat_path if os.path.exists(bat_path) else (shutil.which("holehe") or r"env\Scripts\holehe.exe")
        cmd = [holehe_exe, email, "--only-used"]
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        raw_output = result.stdout.strip() if result.stdout else ""

        registered = []
        for line in raw_output.splitlines():
            line = line.strip()
            if line.startswith("[+]"):
                domain = line.replace("[+]", "").strip()
                if "Email used" not in domain and "websites checked" not in domain and "Rate limit" not in domain:
                    registered.append(domain)
        return registered
    except Exception:
        return []

def generate_html_report(data, filename):
    darkweb_matches = data.get("results", {}).get("darkweb_exposure", {}).get("matches", [])
    onion_rows = "".join([f"<tr><td style='color:#f43f5e;'>{i['title']}</td><td style='font-family:monospace; color:#38bdf8;'>{i['onion_url']}</td><td>{i['snippet']}</td></tr>" for i in darkweb_matches])
    if not onion_rows:
        onion_rows = "<tr><td colspan='3' style='text-align:center;'>Tidak ada temuan di Dark Web.</td></tr>"

    breach_tags = "".join([f"<span style='background:#881337; color:#fecdd3; padding:4px 8px; margin:2px; display:inline-block; border-radius:4px;'>{b}</span>" for b in data.get("results", {}).get("data_breach_history", {}).get("exposed_in", [])])
    site_tags = "".join([f"<span style='background:#1e3a8a; color:#bfdbfe; padding:4px 8px; margin:2px; display:inline-block; border-radius:4px;'>{s}</span>" for s in data.get("results", {}).get("registered_platforms", {}).get("sites", [])])

    html_content = f"""
    <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Darkweb Monitoring Report - {data['target']}</title>
    <style>body{{font-family:sans-serif; background:#0f172a; color:#e2e8f0; padding:30px;}} table{{width:100%; border-collapse:collapse; background:#1e293b; margin-top:15px;}} th,td{{padding:12px; border:1px solid #334155;}}</style>
    </head><body>
    <h1>DARKWEB MONITORING REPORT: {data['target']}</h1><p>Generated: {data['timestamp']}</p>
    <h2>Dark Web Findings</h2><table><thead><tr><th>Title</th><th>URL</th><th>Snippet</th></tr></thead><tbody>{onion_rows}</tbody></table>
    <h2>Data Breaches</h2><div>{breach_tags}</div>
    <h2>Registered Sites</h2><div>{site_tags}</div>
    </body></html>
    """
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"\n[+] SUCCESS: File HTML disimpan ke -> {filename}")


# ==========================================
# 2. ASYNC CORE PIPELINE & DATA PARSER
# ==========================================
async def run_scan_pipeline(target):
    loop = asyncio.get_running_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        darkweb_res, stealer_res, breach_res, holehe_res = await asyncio.gather(
            loop.run_in_executor(pool, search_darkweb_ahmia, target),
            loop.run_in_executor(pool, check_stealer_log_sync, target),
            loop.run_in_executor(pool, check_public_breaches_sync, target),
            loop.run_in_executor(pool, check_holehe_sync, target)
        )

    # --- STRUCTURING PII EXPOSURE & STEALER LOGS FOR TASKS.PY ---
    stealer_logs_list = []
    pii_exposures_list = []

    # 1. Parse Stealer Log Data
    if stealer_res.get("stealer_logs_count", 0) > 0:
        stealer_logs_list.append({
            "malware_name": "HudsonRock Stealer Intelligence",
            "infected_host": "COMPROMISED_DEVICE",
            "infected_url": f"Multiple Services for {target}",
            "has_cookies": True
        })
        # PII Exposure dari Stealer
        pii_exposures_list.append({
            "type": PIIType.SESSION_COOKIE,
            "value": f"Session cookies hijacked ({stealer_res.get('stealer_logs_count')} logs)",
            "has_cookies": True,
            "source": "Stealer Malware Logs"
        })
        if stealer_res.get("compromised_passwords", 0) > 0:
            pii_exposures_list.append({
                "type": PIIType.PASSWORD_PLAIN,
                "value": f"{stealer_res.get('compromised_passwords')} Compromised Plaintext Passwords",
                "has_cookies": True,
                "source": "Stealer Logs Feed"
            })

    # 2. Parse Data Breaches
    exposed_breaches = breach_res.get("exposed_in", [])
    if isinstance(exposed_breaches, list):
        for breach in exposed_breaches:
            pii_exposures_list.append({
                "type": PIIType.PASSWORD_HASH,
                "value": f"Credential exposure on {breach}",
                "has_cookies": False,
                "source": f"Data Breach: {breach}"
            })

    # 3. Target Email Itself
    pii_exposures_list.append({
        "type": PIIType.EMAIL,
        "value": target,
        "has_cookies": False,
        "source": "Target Identifier"
    })

    return {
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stealer_logs": stealer_logs_list,
        "pii_exposures": pii_exposures_list,
        "results": {
            "darkweb_exposure": darkweb_res,
            "stealer_malware_logs": stealer_res,
            "data_breach_history": breach_res,
            "registered_platforms": {"total": len(holehe_res), "sites": holehe_res}
        }
    }


# ==========================================
# 3. FASTAPI SERVER & ENDPOINTS
# ==========================================
app = FastAPI(
    title="UBA Darkweb Monitoring Platform API",
    description="Engine terpadu pemindaian Darkweb Data Breach, Stealer Logs, dan Credential Validator.",
    version="2.1.0"
)

@app.get("/")
async def root_redirect():
    return RedirectResponse(url="/docs")


# --- ASYNC QUEUE ENDPOINTS ---

@app.post("/api/v1/scan")
def trigger_darkweb_scan_async(target: str = Query(..., description="Email/Domain Target"), db: Session = Depends(get_db)):
    """
    [ASYNC] Trigger scanning tanpa memblokir UI. Mengembalikan Job ID seketika.
    """
    from tasks import execute_darkweb_scan_job

    # 1. Simpan atau ambil asset
    asset = db.query(MonitoredAsset).filter(MonitoredAsset.asset_value == target).first()
    if not asset:
        asset_type = "EMAIL" if "@" in target else "DOMAIN"
        asset = MonitoredAsset(asset_type=asset_type, asset_value=target)
        db.add(asset)
        db.commit()
        db.refresh(asset)

    # 2. Buat record scan job
    job = ScanJob(asset_id=asset.id, job_type="FULL_DARKWEB_SCAN", status="PENDING")
    db.add(job)
    db.commit()
    db.refresh(job)

    # 3. Lempar task ke Redis Queue
    execute_darkweb_scan_job.delay(str(job.id), target, str(asset.id))

    return {
        "status": "QUEUED",
        "job_id": str(job.id),
        "target": target,
        "message": "Scan job successfully queued in Redis"
    }


@app.get("/api/v1/jobs/{job_id}")
def check_job_status(job_id: str, db: Session = Depends(get_db)):
    """
    [ASYNC] Endpoint Polling untuk mengecek status & mengambil hasil PII Exposure / Stealer Logs.
    """
    try:
        uuid_obj = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Format UUID tidak valid")

    job = db.query(ScanJob).filter(ScanJob.id == uuid_obj).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job ID tidak ditemukan")

    # Struktur Agregasi PII Exposure untuk UI Dashboard
    pii_summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "details": []
    }

    if job.status in ["COMPLETED", "SUCCESS"]:
        # Agregasi data PII Exposures
        pii_records = db.query(PIIExposure).filter(PIIExposure.job_id == job.id).all()
        for pii in pii_records:
            risk_key = pii.risk_level.value if hasattr(pii.risk_level, 'value') else str(pii.risk_level)
            if risk_key in pii_summary:
                pii_summary[risk_key] += 1
            
            pii_type_str = pii.pii_type.value if hasattr(pii.pii_type, 'value') else str(pii.pii_type)
            pii_summary["details"].append({
                "type": pii_type_str,
                "value": pii.raw_value,
                "risk": risk_key,
                "source": pii.source
            })

        # Ambil Stealer Logs
        stealer_records = db.query(StealerLog).filter(StealerLog.job_id == job.id).all()
        stealer_summary = [
            {
                "malware": s.malware_name,
                "host": s.infected_host,
                "url": s.infected_url,
                "has_cookies": s.has_cookies
            } for s in stealer_records
        ]

        # Ambil Raw Leak Records
        leaks = db.query(DarkwebLeakRecord).filter(DarkwebLeakRecord.asset_id == job.asset_id).all()
        leak_summary = [
            {
                "id": str(leak.id),
                "source_type": leak.source_type,
                "title": leak.breach_title,
                "raw_data": leak.raw_data,
                "discovered_at": leak.discovered_at.strftime("%Y-%m-%d %H:%M:%S") if leak.discovered_at else None
            } for leak in leaks
        ]
    else:
        stealer_summary = []
        leak_summary = []

    return {
        "job_id": str(job.id),
        "target": job.asset.asset_value if job.asset else "",
        "status": job.status,
        "error": job.error_message,
        "completed_at": job.completed_at.strftime("%Y-%m-%d %H:%M:%S") if job.completed_at else None,
        "pii_exposure": pii_summary,
        "stealer_logs": stealer_summary,
        "raw_leaks": leak_summary
    }


# --- LEGACY / SYNCHRONOUS ENDPOINTS ---

@app.get("/api/scan")
async def api_scan_endpoint(target: str):
    return await run_scan_pipeline(target)

@app.get("/api/validate/cpanel")
async def validate_cpanel_endpoint(url: str, user: str, pwd: str):
    loop = asyncio.get_running_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, check_cpanel, url, user, pwd)
    return result

@app.get("/api/validate")
async def generic_validate_endpoint(
    service_type: str = Query("cpanel", description="Jenis service: 'cpanel', 'ftp', atau 'basic_auth'"),
    url: str = Query(..., description="Target Host / URL"),
    user: str = Query(..., description="Username"),
    pwd: str = Query(..., description="Password")
):
    loop = asyncio.get_running_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        if service_type.lower() == "ftp":
            return await loop.run_in_executor(pool, check_ftp, url, user, pwd)
        elif service_type.lower() == "basic_auth":
            return await loop.run_in_executor(pool, check_basic_auth, url, user, pwd)
        else:
            return await loop.run_in_executor(pool, check_cpanel, url, user, pwd)


# ==========================================
# 4. CLI ARGUMENT PARSER
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UBA Dark Web & Threat Intelligence Engine")
    parser.add_argument("--target", "-t", type=str, help="Email/Username target yang ingin discan")
    parser.add_argument("--report", "-r", action="store_true", help="Generate file HTML hasil pemindaian")
    parser.add_argument("--api", action="store_true", help="Jalankan REST API Server (FastAPI)")

    args = parser.parse_args()

    if args.api:
        import uvicorn
        print("[*] Starting UBA Darkweb Monitoring REST API Server on http://127.0.0.1:8000 ...")
        uvicorn.run(app, host="127.0.0.1", port=8000)
    else:
        target = args.target if args.target else input("Masukkan Target Email / Username: ").strip()
        if target:
            scan_output = asyncio.run(run_scan_pipeline(target))
            print("================--- [ FINAL RESULTS ] ---================")
            print(json.dumps(scan_output, indent=4))
            print("=========================================================")

            if args.report:
                filename = f"report_{target.replace('@', '_')}.html"
                generate_html_report(scan_output, filename)