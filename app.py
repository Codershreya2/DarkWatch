from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st
import hashlib  # ADDED: Password hashing ke liye

st.set_page_config(
    page_title="DarkWatch",
    page_icon="🛡️",
    layout="wide"
)

# ==========================================
# 🛡️ PILLAR 1: IDENTITY SECURITY (Auth & RBAC)
# ==========================================

# 1. Hashed User Database (No Plain Text Passwords)
# Passwords: admin -> admin123 | analyst -> analyst123
USER_DB = {
    "admin": {
        "password_hash": "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9", 
        "role": "Admin"
    },
    "analyst1": {
        "password_hash": "237930811b5e523f03b2907de8627bcbd5eb994966fb94b2db0f81df6886e09a", 
        "role": "Analyst"
    }
}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Session State Initialize
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = ''
    st.session_state['role'] = ''

# 2. Login Screen (Agar user logged in nahi hai)
if not st.session_state['logged_in']:
    st.title("🔐 DarkWatch - Secure Access")
    st.markdown("⚠️ **Restricted Area:** Only authorized SOC personnel allowed.")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("login_form"):
            st.subheader("Authentication")
            entered_user = st.text_input("Username")
            entered_pass = st.text_input("Password", type="password")
            submit_btn = st.form_submit_button("Login")
            
            if submit_btn:
                # Validate User
                if entered_user in USER_DB and USER_DB[entered_user]["password_hash"] == hash_password(entered_pass):
                    st.session_state['logged_in'] = True
                    st.session_state['username'] = entered_user
                    st.session_state['role'] = USER_DB[entered_user]["role"]
                    st.rerun() # Refresh page to show dashboard
                else:
                    st.error("❌ Access Denied: Invalid Credentials")
                    
    st.stop() # STOP SCRIPT HERE. Bina login ke data load nahi hoga!

# ==========================================
# DASHBOARD STARTS HERE (Only for Authenticated Users)
# ==========================================

# 3. RBAC Sidebar UI (User Role Info & Logout)
st.sidebar.markdown(f"👤 **User:** {st.session_state['username']}")
st.sidebar.markdown(f"🛡️ **Role:** {st.session_state['role']}")

# RBAC Test: Admin specific tools
if st.session_state['role'] == 'Admin':
    st.sidebar.success("✅ Admin Privileges Active")
else:
    st.sidebar.info("👁️ Analyst Mode (Read-Only)")

if st.sidebar.button("Logout"):
    st.session_state['logged_in'] = False
    st.session_state['username'] = ''
    st.session_state['role'] = ''
    st.rerun()

st.sidebar.divider()

# ---------------- ORIGINAL DATA LOADING ----------------

DATA_FILE = Path(__file__).parent / "data" / "threats.csv"

try:
    data = pd.read_csv(DATA_FILE)
except FileNotFoundError:
    st.error(f"CSV file not found: {DATA_FILE}")
    st.stop()
except Exception as error:
    st.error(f"Unable to load threat data: {error}")
    st.stop()

required_columns = {
    "threat_id", "threat_type", "severity", 
    "source", "country", "date", "status"
}

missing_columns = required_columns - set(data.columns)
if missing_columns:
    st.error(f"Missing required columns: {', '.join(sorted(missing_columns))}")
    st.stop()

data["date"] = pd.to_datetime(data["date"], errors="coerce")

st.title("🛡️ DarkWatch")
st.subheader("Dark Web Threat Intelligence Dashboard")
st.write("Monitor, analyze and visualize simulated cyber threat intelligence data.")


# ---------------- SIDEBAR FILTERS ----------------

st.sidebar.header("Filter Threat Records")

severity_options = sorted(data["severity"].dropna().unique())
country_options = sorted(data["country"].dropna().unique())
status_options = sorted(data["status"].dropna().unique())

selected_severity = st.sidebar.multiselect("Severity", options=severity_options, default=severity_options)
selected_countries = st.sidebar.multiselect("Country", options=country_options, default=country_options)
selected_status = st.sidebar.multiselect("Status", options=status_options, default=status_options)


# ---------------- FILTER DATA ----------------

filtered_data = data[
    data["severity"].isin(selected_severity)
    & data["country"].isin(selected_countries)
    & data["status"].isin(selected_status)
].copy()

st.divider()

# ---------------- METRICS ----------------

col1, col2, col3 = st.columns(3)
total_threats = len(filtered_data)
high_risk = len(filtered_data[filtered_data["severity"].isin(["High", "Critical"])])
active_alerts = len(filtered_data[filtered_data["status"].str.lower() == "active"])

with col1:
    st.metric("Total Threats", total_threats)
with col2:
    st.metric("High Risk Threats", high_risk)
with col3:
    st.metric("Active Alerts", active_alerts)

st.divider()

# ---------------- EMPTY STATE ----------------

if filtered_data.empty:
    st.warning("No threat records match the selected filters.")
    st.stop()

# ---------------- ANALYTICS ----------------

st.subheader("Threat Analytics")
chart_col1, chart_col2 = st.columns(2)

# Severity Chart
severity_counts = filtered_data["severity"].value_counts().reindex(["Low", "Medium", "High", "Critical"]).dropna().reset_index()
severity_counts.columns = ["severity", "count"]
severity_chart = px.bar(severity_counts, x="severity", y="count", color="severity", title="Threats by Severity", text="count")
with chart_col1:
    st.plotly_chart(severity_chart, use_container_width=True)

# Threat Type Chart
threat_type_counts = filtered_data["threat_type"].value_counts().reset_index()
threat_type_counts.columns = ["threat_type", "count"]
threat_type_chart = px.bar(threat_type_counts, x="threat_type", y="count", color="threat_type", title="Threats by Type", text="count")
with chart_col2:
    st.plotly_chart(threat_type_chart, use_container_width=True)

chart_col3, chart_col4 = st.columns(2)

# Country Chart
country_counts = filtered_data["country"].value_counts().reset_index()
country_counts.columns = ["country", "count"]
country_chart = px.bar(country_counts, x="country", y="count", color="country", title="Threats by Country", text="count")
with chart_col3:
    st.plotly_chart(country_chart, use_container_width=True)

# Source Chart
source_counts = filtered_data["source"].value_counts().reset_index()
source_counts.columns = ["source", "count"]
source_chart = px.bar(source_counts, x="source", y="count", color="source", title="Threats by Source", text="count")
with chart_col4:
    st.plotly_chart(source_chart, use_container_width=True)

# Trend Chart
daily_threats = filtered_data.dropna(subset=["date"]).groupby("date").size().reset_index(name="count").sort_values("date")
if not daily_threats.empty:
    trend_chart = px.line(daily_threats, x="date", y="count", markers=True, title="Daily Threat Trend")
    st.plotly_chart(trend_chart, use_container_width=True)

# ---------------- TABLE ----------------

st.subheader("Filtered Threat Records")
display_data = filtered_data.copy()
display_data["date"] = display_data["date"].dt.strftime("%Y-%m-%d")

st.dataframe(display_data, use_container_width=True, hide_index=True)
