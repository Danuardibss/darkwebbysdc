import streamlit as st
import requests
import pandas as pd

st.set_page_config(page_title="UBA Dark Web Intelligence", page_icon="🛡️", layout="wide")

st.title("UBA Threat Intelligence & Dark Web Monitor")
st.caption("Engine Monitoring Data Breach & Threat Intelligence")

# Menu Utama Berbasis Tab
main_tab1, main_tab2 = st.tabs(["🔍 OSINT Email Scan", "🔑 Credential Validator"])

# ==========================================
# TAB 1: OSINT EMAIL SCANNER (KODE ASLI KAMU)
# ==========================================
with main_tab1:
    target_input = st.text_input("Masukkan Target Email / Username:", placeholder="contoh: 123@gmail.com")

    if st.button("Run Scanning", type="primary"):
        if not target_input:
            st.warning("Input the target is required!")
        else:
            with st.spinner("Requesting API Server..."):
                try:
                    # Memanggil API FastAPI yang sedang jalan di port 8000
                    response = requests.get(f"http://127.0.0.1:8000/api/scan?target={target_input}")
                    if response.status_code == 200:
                        data = response.json()
                        res = data.get("results", {})

                        st.success(f"Scanning Process is already completed: {data.get('target')}")
                        
                        # Metric Cards
                        col1, col2, col3 = st.columns(3)
                        col1.metric("Data Breaches", res.get("data_breach_history", {}).get("total_breaches", 0))
                        col2.metric("Stealer Logs", res.get("stealer_malware_logs", {}).get("stealer_logs_count", 0))
                        col3.metric("Registered Sites", res.get("registered_platforms", {}).get("total", 0))

                        st.divider()

                        # Tab Detail
                        tab1, tab2, tab3 = st.tabs(["Data Breaches", "Dark Web Findings", "Registered Accounts"])

                        with tab1:
                            st.subheader("Riwayat Data Breach")
                            breaches = res.get("data_breach_history", {}).get("exposed_in", [])
                            if breaches:
                                st.write(breaches)
                            else:
                                st.info("Tidak terdeteksi kebocoran data publik.")

                        with tab2:
                            st.subheader("Dark Web Findings")
                            matches = res.get("darkweb_exposure", {}).get("matches", [])
                            if matches:
                                st.dataframe(matches)
                            else:
                                st.info("Tidak ada jejak di indeks Dark Web.")

                        with tab3:
                            st.subheader("Registered Platforms")
                            sites = res.get("registered_platforms", {}).get("sites", [])
                            if sites:
                                st.write(sites)
                            else:
                                st.info("Tidak ada footprint platform terdeteksi.")

                except Exception as e:
                    st.error(f"Gagal terhubung ke API Server. Pastikan 'python main.py --api' sedang berjalan! Error: {e}")

# ==========================================
# TAB 2: CREDENTIAL VALIDATOR
# ==========================================
with main_tab2:
    st.subheader("cPanel & Webmail Live Credential Validator")
    st.caption("Uji keabsahan kredensial hasil temuan leak atau stealer log secara live.")

    # Form Single Credential Test
    col_url, col_user, col_pass = st.columns([2, 1, 1])
    with col_url:
        cpanel_url = st.text_input("Target URL:", placeholder="https://example.com:2083")
    with col_user:
        cpanel_user = st.text_input("Username:", placeholder="admin")
    with col_pass:
        cpanel_pass = st.text_input("Password:", type="password", placeholder="••••••••")

    if st.button("Validate Credential", type="primary"):
        if not cpanel_url or not cpanel_user or not cpanel_pass:
            st.warning("URL, Username, dan Password wajib diisi!")
        else:
            with st.spinner("Testing live login ke target server..."):
                try:
                    api_url = "http://127.0.0.1:8000/api/validate/cpanel"
                    params = {
                        "url": cpanel_url.strip(),
                        "user": cpanel_user.strip(),
                        "pwd": cpanel_pass.strip()
                    }
                    res = requests.get(api_url, params=params, timeout=10)
                    
                    if res.status_code == 200:
                        result = res.json()
                        status = result.get("status")
                        msg = result.get("message", "")

                        if status == "VALID":
                            st.success(f"🟩 **LEGIT / VALID:** {msg}")
                            if "redirect_url" in result:
                                st.info(f"Redirect URL: {result.get('redirect_url')}")
                        elif status == "INVALID":
                            st.error(f"🟥 **INVALID:** {msg}")
                        else:
                            st.warning(f"⚠️ **{status}:** {msg}")
                    else:
                        st.error(f"API Server Error HTTP {res.status_code}")
                except Exception as e:
                    st.error(f"Gagal terhubung ke API Validator: {e}")

    st.divider()

    # Bulk Testing via Text Area
    with st.expander("⚡ Bulk Testing (Pengujian Banyak Credential Sekaligus)"):
        st.caption("Masukkan list credential dengan format per baris: `URL|USERNAME|PASSWORD`")
        bulk_text = st.text_area(
            "List Credential:",
            placeholder="https://site1.com:2083|user1|pass1\nhttps://site2.com:2083|user2|pass2",
            height=130
        )
        
        if st.button("Run Bulk Validation"):
            if not bulk_text.strip():
                st.warning("Masukkan setidaknya 1 baris credential!")
            else:
                lines = [line.strip() for line in bulk_text.strip().split("\n") if line.strip()]
                results = []
                
                progress_bar = st.progress(0)
                for idx, line in enumerate(lines):
                    if "|" in line:
                        parts = line.split("|")
                        if len(parts) >= 3:
                            u, usr, pwd = parts[0].strip(), parts[1].strip(), parts[2].strip()
                            try:
                                res = requests.get(
                                    "http://127.0.0.1:8000/api/validate/cpanel", 
                                    params={"url": u, "user": usr, "pwd": pwd}, 
                                    timeout=8
                                )
                                if res.status_code == 200:
                                    data = res.json()
                                    st_code = data.get("status")
                                    message = data.get("message")
                                else:
                                    st_code = "ERROR"
                                    message = f"HTTP {res.status_code}"
                            except Exception as err:
                                st_code = "ERROR"
                                message = str(err)

                            status_display = "🟩 VALID" if st_code == "VALID" else ("🟥 INVALID" if st_code == "INVALID" else "⚠️ " + str(st_code))
                            results.append({
                                "Target URL": u,
                                "Username": usr,
                                "Status": status_display,
                                "Keterangan": message
                            })
                    progress_bar.progress((idx + 1) / len(lines))

                if results:
                    st.dataframe(pd.DataFrame(results), use_container_width=True)
                else:
                    st.error("Format input tidak sesuai! Gunakan pemisah (`|`).")