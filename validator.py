import requests

def check_cpanel_login(target_url, username, password):
    """
    Validasi kredensial cPanel / Webmail.
    target_url: misal 'https://sps-domain.com:2083' atau 'https://sps-domain.com/cpanel'
    """
    login_url = f"{target_url.rstrip('/')}/login/?login_only=1"
    payload = {
        "user": username,
        "pass": password
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    
    try:
        # Timeout pendek biar scan gak menggantung
        response = requests.post(login_url, data=payload, headers=headers, timeout=5, verify=False)
        
        if response.status_code == 200:
            res_json = response.json()
            # cPanel API biasanya balikin status 1 kalau login sukses
            if res_json.get("status") == 1 or "security_token" in res_json:
                return {
                    "status": "VALID",
                    "message": "Credential LEGIT! Login Berhasil.",
                    "redirect_url": res_json.get("redirect")
                }
            else:
                return {"status": "INVALID", "message": "Password salah / kadaluarsa."}
                
        elif response.status_code == 401:
             return {"status": "INVALID", "message": "Unauthorized (401)."}
             
        return {"status": "UNKNOWN", "message": f"Server merespon dengan HTTP {response.status_code}"}
        
    except requests.exceptions.Timeout:
        return {"status": "ERROR", "message": "Connection Timeout (Server down / Port tertutup)."}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

# ==========================================
# TEST SKRIP MANDIRI
# ==========================================
if __name__ == "__main__":
    print("=== TEST CREDENTIAL VALIDATOR ===")
    target = input("Masukkan URL Target cPanel (misal: https://example.com:2083): ").strip()
    user = input("Username: ").strip()
    pwd = input("Password: ").strip()
    
    print("\n[*] Mengetes validasi login...")
    result = check_cpanel_login(target, user, pwd)
    print(f"[RESULT]: {result}")