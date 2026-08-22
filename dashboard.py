import streamlit as st
import requests

st.set_page_config(page_title="UBA Dark Web Intelligence", page_icon="🛡️", layout="wide")

st.title("UBA Threat Intelligence & Dark Web Monitor")
st.caption("Engine Monitoring Data Breach")

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