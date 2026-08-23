import requests
import ftplib

def check_cpanel(target_url, username, password):
    """Validasi Kredensial cPanel / Webmail"""
    login_url = f"{target_url.rstrip('/')}/login/?login_only=1"
    payload = {"user": username, "pass": password}
    try:
        res = requests.post(login_url, data=payload, timeout=5, verify=False)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == 1 or "security_token" in data:
                return {"status": "VALID", "message": "Login cPanel Berhasil."}
        return {"status": "INVALID", "message": "Kredensial cPanel Salah/Kadaluarsa."}
    except Exception as e:
        return {"status": "ERROR", "message": f"Koneksi gagal: {str(e)}"}

def check_ftp(host, username, password, port=21):
    """Validasi Kredensial FTP Server"""
    # Bersihkan prefix URL jika ada
    clean_host = host.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    try:
        ftp = ftplib.FTP()
        ftp.connect(clean_host, int(port), timeout=5)
        ftp.login(username, password)
        ftp.quit()
        return {"status": "VALID", "message": "Akses FTP Server Berhasil."}
    except ftplib.error_perm:
        return {"status": "INVALID", "message": "Kredensial FTP Ditolak (530 User/Pass wrong)."}
    except Exception as e:
        return {"status": "ERROR", "message": f"FTP Error: {str(e)}"}

def check_basic_auth(target_url, username, password):
    """Validasi HTTP Basic Auth (Router/Admin Panel/Internal API)"""
    try:
        res = requests.get(target_url, auth=(username, password), timeout=5, verify=False)
        if res.status_code in [200, 301, 302]:
            return {"status": "VALID", "message": f"Authentication Berhasil (HTTP {res.status_code})."}
        elif res.status_code == 401:
            return {"status": "INVALID", "message": "Unauthorized (HTTP 401)."}
        return {"status": "UNKNOWN", "message": f"HTTP Response Code: {res.status_code}"}
    except Exception as e:
        return {"status": "ERROR", "message": f"HTTP Auth Error: {str(e)}"}