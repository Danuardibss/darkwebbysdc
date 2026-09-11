HANDOVER & PROJECT STATUS

Semua source code terbaru udah dipush ke branch main.

Last update:
Sistem udah ga pake mock data lagi. Semua pipeline pencarian udah terhubung ke live data (API & Scraper).

Fitur yang udah selesai:
1. DB & Task Queue: PostgreSQL running di container (port 5433) dan Redis broker udah terhubung dengan Celery worker.
2. Scrapers Module:
   - HudsonRock (Cavalier API): Udah bisa tarik log komputer terinfeksi stealer malware berdasarkan target email.
   - Holehe: Udah bisa checking registrasi akun email di 120+ situs.
   - BreachDirectory: Script API RapidAPI udah terpasang di folder scrapers.
3. UI Streamlit: Udah bisa trigger job pemindaian ke Celery worker dan nampilin data dari database.

NOTE & TROUBLESHOOTING:
- Kalau Celery kena error psycopg2.OperationalError (connection refused ke port 5433), itu karena Docker PostgreSQL belum siap pas Celery nyala. Solusinya: restart Docker Desktop, pastiin container Postgres statusnya Up (cek via 'docker ps'), baru jalanin workernya.
- Selalu aktifkan venv (.\env\Scripts\Activate.ps1) tiap buka terminal baru.

NEXT STEPS / TODO BUAT DEV SELANJUTNYA:
1. Local Dump Indexer: Bikin script parser file CSV/TXT ke PostgreSQL (tabel local_leak_archive) supaya bisa query NIK, KTP, atau No HP offline dari file dump lokal.
2. Input Regex Auto-Detect: Bikin validator di FastAPI supaya sistem otomatis membedakan mana input NIK (16 digit), Email, atau Nomor HP (+62).
3. UI Masking & Risk Score: Tambahin fitur masking data sensitif di Streamlit (contoh: NIK 327104******0002) dan kalkulasi skor risiko total temuan.