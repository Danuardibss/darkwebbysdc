import subprocess
import json
import os
import shutil
import asyncio
import concurrent.futures
import requests
import argparse
from bs4 import BeautifulSoup
from datetime import datetime
from fastapi import FastAPI, Query
from fastapi.responses import RedirectResponse

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

# Alias untuk backwards compatibility
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
                "status": "COMPROMISED",
                "stealer_logs_count": data.get("stealer_logs_count", 0),
                "compromised_passwords": data.get("passwords_count", 0)
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
    onion_rows = "".join([f"<tr><td style='color:#f43f5e;'>{i['title']}</td><td style='font-family:monospace; color:#38bdf8;'>{i['onion_url']}</td><td>{i['snippet']}</td></tr>" for i in data["results"]["darkweb_exposure"]["matches"]])
    if not onion_rows:
        onion_rows = "<tr><td colspan='3' style='text-align:center;'>Tidak ada temuan di Dark Web.</td></tr>"

    breach_tags = "".join([f"<span style='background:#881337; color:#fecdd3; padding:4px 8px; margin:2px; display:inline-block; border-radius:4px;'>{b}</span>" for b in data["results"]["data_breach_history"].get("exposed_in", [])])
    site_tags = "".join([f"<span style='background:#1e3a8a; color:#bfdbfe; padding:4px 8px; margin:2px; display:inline-block; border-radius:4px;'>{s}</span>" for s in data["results"]["registered_platforms"]["sites"]])

    html_content = f"""
    <!DOCTYPE html><html><head><meta charset="UTF-8"><title>OSINT Report - {data['target']}</title>
    <style>body{{font-family:sans-serif; background:#0f172a; color:#e2e8f0; padding:30px;}} table{{width:100%; border-collapse:collapse; background:#1e293b; margin-top:15px;}} th,td{{padding:12px; border:1px solid #334155;}}</style>
    </head><body>
    <h1>REPORT TARGET: {data['target']}</h1><p>Generated: {data['timestamp']}</p>
    <h2>Dark Web Findings</h2><table><thead><tr><th>Title</th><th>URL</th><th>Snippet</th></tr></thead><tbody>{onion_rows}</tbody></table>
    <h2>Data Breaches ({data['results']['data_breach_history'].get('total_breaches',0)})</h2><div>{breach_tags}</div>
    <h2>Registered Sites ({data['results']['registered_platforms']['total']})</h2><div>{site_tags}</div>
    </body></html>
    """
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"\n[+] SUCCESS: File HTML disimpan ke -> {filename}")

# ==========================================
# 2. ASYNC CORE PIPELINE
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

    return {
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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
    title="UBA OSINT & Threat Intelligence API",
    description="Engine terpadu pemindaian OSINT data breach dan validator kredensial infrastruktur.",
    version="2.0.0"
)

@app.get("/")
async def root_redirect():
    """Otomatis mengarahkan user dari / ke halaman dokumentasi interaktif /docs."""
    return RedirectResponse(url="/docs")

@app.get("/api/scan")
async def api_scan_endpoint(target: str):
    """Endpoint pemindaian OSINT Email/Username."""
    return await run_scan_pipeline(target)

@app.get("/api/validate/cpanel")
async def validate_cpanel_endpoint(url: str, user: str, pwd: str):
    """Endpoint cPanel lama (tetap dipertahankan agar dashboard tidak error)."""
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
    """Endpoint Universal Multi-Protocol Credential Validator."""
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
        print("[*] Starting UBA Threat Intel REST API Server on http://127.0.0.1:8000 ...")
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