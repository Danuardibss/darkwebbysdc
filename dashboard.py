import streamlit as st
import requests
import pandas as pd
import time

# ==========================================
# 1. STREAMLIT CONFIG & CUSTOM STYLING
# ==========================================
st.set_page_config(
    page_title="UBA Darkweb & Threat Intel Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

API_BASE_URL = "http://127.0.0.1:8000"

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, sans-serif;
    }
    code, pre, div[data-baseweb="input"] input, textarea, .stDataFrame {
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0d1117;
        border-right: 1px solid #30363d;
    }
    
    /* Hide Instructions Input */
    [data-testid="stInputInstructions"] { display: none !important; }
    
    /* Custom Risk Badges */
    .badge-critical { background-color: #7f1d1d; color: #fca5a5; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
    .badge-high { background-color: #7c2d12; color: #fdba74; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
    .badge-medium { background-color: #713f12; color: #fde047; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
    .badge-low { background-color: #1e3a8a; color: #93c5fd; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
    
    /* Card Container */
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 15px;
        border-radius: 6px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# Session State Initialization
if "current_job_id" not in st.session_state:
    st.session_state.current_job_id = None
if "scan_data" not in st.session_state:
    st.session_state.scan_data = None
if "target_email" not in st.session_state:
    st.session_state.target_email = ""


# ==========================================
# 2. SIDEBAR NAVIGATION
# ==========================================
with st.sidebar:
    st.title("🛡️ ThreatIntel SOC")
    st.caption("Darkweb & PII Monitoring Console v2.1")
    st.divider()

    menu = st.radio(
        "MODULES",
        [
            "🎯 Target Scanner",
            "🪪 PII Exposure Intel",
            "👾 Stealer Log Intelligence",
            "🧅 Darkweb Onion Matches",
            "🔑 Credential Live Validator"
        ],
        index=0
    )

    st.divider()
    if st.session_state.target_email:
        st.write("**Active Target:**")
        st.code(st.session_state.target_email)
        if st.session_state.current_job_id:
            st.caption(f"Job ID: `{st.session_state.current_job_id[:8]}...`")


# Helper Function to Fetch Job Data
def fetch_job_results(job_id):
    try:
        res = requests.get(f"{API_BASE_URL}/api/v1/jobs/{job_id}", timeout=10)
        if res.status_code == 200:
            return res.json()
    except Exception as e:
        st.error(f"Failed to fetch job status: {e}")
    return None


# ==========================================
# MODULE 1: TARGET SCANNER
# ==========================================
if menu == "🎯 Target Scanner":
    st.header("🎯 Target Asset OSINT Scanner")
    st.caption("Pemindaian asynchronous ke jejaring Dark Web, Stealer Logs, dan Data Breach database.")

    col_in, col_btn = st.columns([4, 1])
    with col_in:
        target_input = st.text_input("Target Email / Domain", value=st.session_state.target_email, placeholder="user@company.com / domain.com")
    with col_btn:
        st.write(" ")
        st.write(" ")
        run_click = st.button("Start Scan", type="primary", use_container_width=True)

    if run_click:
        if not target_input.strip():
            st.warning("Target parameter is required.")
        else:
            st.session_state.target_email = target_input.strip()
            with st.spinner("Queueing scan job in backend..."):
                try:
                    res = requests.post(f"{API_BASE_URL}/api/v1/scan?target={target_input.strip()}", timeout=10)
                    if res.status_code == 200:
                        job_data = res.json()
                        st.session_state.current_job_id = job_data.get("job_id")
                        st.success(f"Job Queued Successfully! (Job ID: {st.session_state.current_job_id})")
                    else:
                        st.error(f"Error HTTP {res.status_code}: {res.text}")
                except Exception as e:
                    st.error(f"Connection failure: {e}")

    # Polling & Display Status
    if st.session_state.current_job_id:
        st.divider()
        st.subheader("Scan Job Progress")
        
        data = fetch_job_results(st.session_state.current_job_id)
        if data:
            st.session_state.scan_data = data
            status = data.get("status")

            if status in ["PENDING", "PROCESSING"]:
                st.info(f"⏳ Current Job Status: **{status}**. Fetching updates...")
                time.sleep(2)
                st.rerun()
            elif status in ["COMPLETED", "SUCCESS"]:
                st.success("✅ Pemindaian Selesai!")
                
                # Metrics Row
                pii_summary = data.get("pii_exposure", {})
                m1, m2, m3, m4, m5 = st.columns(5)
                m1.metric("CRITICAL Risks", pii_summary.get("CRITICAL", 0))
                m2.metric("HIGH Risks", pii_summary.get("HIGH", 0))
                m3.metric("MEDIUM Risks", pii_summary.get("MEDIUM", 0))
                m4.metric("LOW Risks", pii_summary.get("LOW", 0))
                m5.metric("Stealer Logs", len(data.get("stealer_logs", [])))

                st.divider()
                st.caption("Pilih menu di bilah samping (sidebar) sebelah kiri untuk melihat detail temuan PII, Stealer Log, dan Link Darkweb.")
            else:
                st.error(f"Scan Job Failed: {data.get('error')}")


# ==========================================
# MODULE 2: PII EXPOSURE INTEL
# ==========================================
elif menu == "🪪 PII Exposure Intel":
    st.header("🪪 PII Exposure Intelligence")
    st.caption("Daftar Personally Identifiable Information (PII) milik target yang bocor di publik atau Darkweb.")

    if not st.session_state.scan_data or not st.session_state.scan_data.get("pii_exposure"):
        st.info("Belum ada data PII. Silakan jalankan pemindaian terlebih dahulu di menu **Target Scanner**.")
    else:
        pii_details = st.session_state.scan_data.get("pii_exposure", {}).get("details", [])
        
        if pii_details:
            df_pii = pd.DataFrame(pii_details)
            
            # Summary Overview
            col_filter, col_stat = st.columns([2, 3])
            with col_filter:
                risk_filter = st.multiselect("Filter Risk Level", options=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
            
            filtered_df = df_pii[df_pii["risk"].isin(risk_filter)] if not df_pii.empty else df_pii
            
            st.dataframe(
                filtered_df,
                column_config={
                    "type": "PII Category",
                    "value": "Exposed Value / Content",
                    "risk": "Risk Level",
                    "source": "Leak Source"
                },
                use_container_width=True,
                hide_index=True
            )
        else:
            st.success("🎉 Tidak terdeteksi adanya PII Exposure berisiko untuk target ini.")


# ==========================================
# MODULE 3: STEALER LOG INTELLIGENCE
# ==========================================
elif menu == "👾 Stealer Log Intelligence":
    st.header("👾 Stealer Malware Log Intelligence")
    st.caption("Data infeksi malware pencuri kredensial (RedLine, Racoon, Vidar, dll.) yang terdeteksi.")

    if not st.session_state.scan_data:
        st.info("Belum ada data Stealer Log. Silakan lakukan pemindaian di menu **Target Scanner**.")
    else:
        stealers = st.session_state.scan_data.get("stealer_logs", [])
        if stealers:
            st.warning(f"🚨 Terdeteksi **{len(stealers)} Log Infeksi Stealer Malware** terkait target ini!")
            
            for idx, log in enumerate(stealers, 1):
                with st.expander(f"Log #{idx} - Malware: {log.get('malware')} (Host: {log.get('host')})", expanded=True):
                    c1, c2 = st.columns(2)
                    c1.write(f"**Infected Host:** `{log.get('host')}`")
                    c1.write(f"**Target Service:** `{log.get('url')}`")
                    c2.write(f"**Session Cookie Hijacked:** `{'YES' if log.get('has_cookies') else 'NO'}`")
                    c2.write(f"**Malware Strain:** `{log.get('malware')}`")
        else:
            st.success("✅ Bersih. Tidak terdeteksi log infeksi Stealer Malware.")


# ==========================================
# MODULE 4: DARKWEB ONION MATCHES
# ==========================================
elif menu == "🧅 Darkweb Onion Matches":
    st.header("🧅 Dark Web Onion Indexing & Leaks")
    st.caption("Hasil crawling dan ekstraksi langsung dari situs Onion & Darkweb Marketplace.")

    if not st.session_state.scan_data:
        st.info("Belum ada data Darkweb. Silakan lakukan pemindaian di menu **Target Scanner**.")
    else:
        leaks = st.session_state.scan_data.get("raw_leaks", [])
        if leaks:
            df_leaks = pd.DataFrame(leaks)
            st.dataframe(
                df_leaks[["source_type", "title", "discovered_at"]],
                column_config={
                    "source_type": "Source",
                    "title": "Leak / Site Title",
                    "discovered_at": "Discovered Date"
                },
                use_container_width=True,
                hide_index=True
            )
            
            st.subheader("Raw Snippets")
            for item in leaks:
                with st.expander(f"📍 {item.get('title')}"):
                    st.json(item.get("raw_data"))
        else:
            st.info("Tidak ditemukan situs Onion atau tautan Darkweb aktif yang memuat keyword target.")


# ==========================================
# MODULE 5: CREDENTIAL LIVE VALIDATION
# ==========================================
elif menu == "🔑 Credential Live Validator":
    st.header("🔑 Credential Live Validator")
    st.caption("Uji keabsahan kredensial hasil bocoran (cPanel, FTP, Basic Authentication).")

    v_tab1, v_tab2 = st.tabs(["Single Account Test", "Bulk Account Test"])

    with v_tab1:
        c_svc, c_url, c_usr, c_pwd = st.columns([1.5, 3, 2, 2])
        with c_svc:
            service_type = st.selectbox("Service", ["cpanel", "ftp", "basic_auth"])
        with c_url:
            target_url = st.text_input("Host / Target URL", placeholder="https://example.com:2083")
        with c_usr:
            username = st.text_input("Username", placeholder="admin")
        with c_pwd:
            password = st.text_input("Password", type="password", placeholder="••••••••")

        if st.button("Validate Credential", type="primary"):
            if not target_url or not username or not password:
                st.warning("All input fields are required.")
            else:
                with st.spinner("Testing live connection..."):
                    try:
                        params = {
                            "service_type": service_type.lower(),
                            "url": target_url.strip(),
                            "user": username.strip(),
                            "pwd": password.strip()
                        }
                        res = requests.get(f"{API_BASE_URL}/api/validate", params=params, timeout=12)
                        if res.status_code == 200:
                            out = res.json()
                            status = out.get("status")
                            msg = out.get("message", "")
                            if status == "VALID":
                                st.success(f"[VALID] {msg}")
                            elif status == "INVALID":
                                st.error(f"[INVALID] {msg}")
                            else:
                                st.warning(f"[{status}] {msg}")
                        else:
                            st.error(f"API Error HTTP {res.status_code}")
                    except Exception as e:
                        st.error(f"Connection failure: {e}")

    with v_tab2:
        st.caption("Format input (1 entry per baris): `URL|USERNAME|PASSWORD`")
        bulk_text = st.text_area("Credential List", placeholder="https://site.com:2083|user1|pass1\n192.168.1.1|root|pass2", height=130)

        if st.button("Run Bulk Validation"):
            if not bulk_text.strip():
                st.warning("Input list cannot be empty.")
            else:
                lines = [line.strip() for line in bulk_text.strip().split("\n") if line.strip()]
                results = []
                prog = st.progress(0)

                for idx, line in enumerate(lines):
                    if "|" in line:
                        parts = line.split("|")
                        if len(parts) >= 3:
                            u, usr, pwd = parts[0].strip(), parts[1].strip(), parts[2].strip()
                            try:
                                res = requests.get(
                                    f"{API_BASE_URL}/api/validate",
                                    params={"service_type": service_type.lower(), "url": u, "user": usr, "pwd": pwd},
                                    timeout=8
                                )
                                if res.status_code == 200:
                                    data = res.json()
                                    st_code = data.get("status")
                                    message = data.get("message")
                                else:
                                    st_code, message = "ERROR", f"HTTP {res.status_code}"
                            except Exception as err:
                                st_code, message = "ERROR", str(err)

                            results.append({"Host": u, "User": usr, "Status": f"[{st_code}]", "Response": message})
                    prog.progress((idx + 1) / len(lines))

                if results:
                    st.dataframe(pd.DataFrame(results), use_container_width=True)