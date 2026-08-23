import streamlit as st
import requests
import pandas as pd

st.set_page_config(
    page_title="Threat Intel Platform",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom Styling - Developer Console Style
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, sans-serif;
    }
    code, pre, stCode, div[data-baseweb="input"] input, textarea, .stDataFrame {
        font-family: 'JetBrains Mono', monospace !important;
    }
    h1, h2, h3 {
        letter-spacing: -0.5px;
    }
    .stButton > button {
        border-radius: 4px;
        font-weight: 500;
        font-size: 13px;
    }

    div[data-testid="stInputInstructions"] {
    display: none !important;
}
</style>
""", unsafe_allow_html=True)

st.title("Threat Intelligence Platform")
st.caption("Internal Security Audit & Breach Monitoring System v2.1")

main_tab1, main_tab2 = st.tabs(["OSINT Scan", "Credential Validator"])

# --- TAB 1: OSINT SCANNER ---
with main_tab1:
    target_input = st.text_input("Target Email / Username", placeholder="user@domain.com")

    if st.button("Run Scan", type="primary"):
        if not target_input.strip():
            st.warning("Target parameter is required.")
        else:
            with st.spinner("Processing API request..."):
                try:
                    res = requests.get(f"http://127.0.0.1:8000/api/scan?target={target_input.strip()}", timeout=30)
                    if res.status_code == 200:
                        data = res.json()
                        results = data.get("results", {})

                        st.success(f"Scan completed: {data.get('target')}")

                        c1, c2, c3 = st.columns(3)
                        c1.metric("Data Breaches", results.get("data_breach_history", {}).get("total_breaches", 0))
                        c2.metric("Stealer Logs", results.get("stealer_malware_logs", {}).get("stealer_logs_count", 0))
                        c3.metric("Registered Sites", results.get("registered_platforms", {}).get("total", 0))

                        st.divider()

                        sub_tab1, sub_tab2, sub_tab3 = st.tabs(["Breach History", "Dark Web Matches", "Registered Platforms"])

                        with sub_tab1:
                            breaches = results.get("data_breach_history", {}).get("exposed_in", [])
                            if breaches:
                                st.write(breaches)
                            else:
                                st.info("No breach records found.")

                        with sub_tab2:
                            matches = results.get("darkweb_exposure", {}).get("matches", [])
                            if matches:
                                st.dataframe(matches, use_container_width=True)
                            else:
                                st.info("No dark web indexed records found.")

                        with sub_tab3:
                            sites = results.get("registered_platforms", {}).get("sites", [])
                            if sites:
                                st.write(sites)
                            else:
                                st.info("No platform footprints detected.")
                    else:
                        st.error(f"API Error HTTP {res.status_code}")
                except Exception as e:
                    st.error(f"Connection failure: {e}")

# --- TAB 2: CREDENTIAL VALIDATOR ---
with main_tab2:
    st.subheader("Credential Live Validator")

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
            with st.spinner("Testing authentication..."):
                try:
                    params = {
                        "service_type": service_type.lower(),
                        "url": target_url.strip(),
                        "user": username.strip(),
                        "pwd": password.strip()
                    }
                    res = requests.get("http://127.0.0.1:8000/api/validate", params=params, timeout=10)
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

    st.divider()

    with st.expander("Bulk Credential Testing"):
        st.caption("Input format (one entry per line): URL|USERNAME|PASSWORD")
        bulk_text = st.text_area(
            "Credential List",
            placeholder="https://site1.com:2083|user1|pass1\n192.168.1.1|root|pass2",
            height=130
        )

        if st.button("Run Bulk Test"):
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
                                    "http://127.0.0.1:8000/api/validate",
                                    params={"service_type": service_type.lower(), "url": u, "user": usr, "pwd": pwd},
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

                            results.append({
                                "Host": u,
                                "User": usr,
                                "Status": f"[{st_code}]",
                                "Response": message
                            })
                    prog.progress((idx + 1) / len(lines))

                if results:
                    st.dataframe(pd.DataFrame(results), use_container_width=True)
                else:
                    st.error("Invalid format. Delimiter '|' is required.")