import requests
import logging

logger = logging.getLogger(__name__)

# Konfigurasi dari RapidAPI Playground kamu
RAPIDAPI_KEY = "6867847bd9mshe4a322d5b2963e4p134851jsndc45adf43dc7"
RAPIDAPI_HOST = "breachdirectory-cheaper-version.p.rapidapi.com"

def fetch_breach_directory(target: str) -> list:
    """
    Mengambil data kebocoran dari BreachDirectory RapidAPI
    """
    url = f"https://{RAPIDAPI_HOST}/"
    querystring = {"term": target, "func": "auto"}
    headers = {
        "x-rapidapi-key": RAPIDAPI_KEY,
        "x-rapidapi-host": RAPIDAPI_HOST
    }

    results = []
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=15)
        if response.status_code == 200:
            data = response.json()
            if data.get("success") and "result" in data:
                for item in data["result"]:
                    results.append({
                        "type": "CREDENTIAL_LEAK",
                        "value": f"Account: {item.get('email', item.get('username', target))} | Secret/Hash: {item.get('password', item.get('sha1', 'N/A'))}",
                        "risk": "CRITICAL" if item.get("password") else "HIGH",
                        "source": item.get("sources", ["BreachDirectory"])[0] if item.get("sources") else "BreachDirectory Dump"
                    })
        else:
            logger.error(f"[BreachAPI] Error HTTP {response.status_code}: {response.text}")
    except Exception as e:
        logger.error(f"[BreachAPI] Connection Failed: {e}")

    return results