from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st
import hashlib
import os
import datetime
import re

st.set_page_config(
    page_title="DarkWatch",
    page_icon="🛡️",
    layout="wide"
)

# ==========================================
# 🛡️ PILLAR 1: IDENTITY SECURITY (Auth & Registration)
# ==========================================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- AUDIT LOGGER (Pillar 5) ---
def log_action(username, action, details):
    """Actions ko chupke se audit.log file me likhta hai"""
    log_file = Path(__file__).parent / "audit.log"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] USER: {username} | ACTION: {action} | DETAILS: {details}\n"
    
    # Mode "a" ka matlab append 
    with open(log_file, "a") as f:
        f.write(log_entry)
# -------------------------------

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = ''
    st.session_state['role'] = ''

# --- NAYA: Database me Lockout fields add kiye ---
if 'user_db' not in st.session_state:
    st.session_state['user_db'] = {
        "admin": {"password_hash": hash_password("admin123"), "role": "Admin", "failed_attempts": 0, "locked_until": None},
        "analyst1": {"password_hash": hash_password("analyst123"), "role": "Analyst", "failed_attempts": 0, "locked_until": None}
    }

if not st.session_state['logged_in']:
    st.title("🔐 DarkWatch - Secure Access")
    st.markdown("⚠️ **Restricted Area:** Only authorized SOC personnel allowed.")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        tab1, tab2 = st.tabs(["🔑 Login", "📝 Register New User"])
        
        with tab1:
            with st.form("login_form"):
                st.subheader("Authentication")
                entered_user = st.text_input("Username")
                entered_pass = st.text_input("Password", type="password")
                submit_btn = st.form_submit_button("Login")
                
                if submit_btn:
                    db = st.session_state['user_db']
                    
                    if entered_user in db:
                        user_info = db[entered_user]
                        
                        # Check 1: Kya account lock hai?
                        if user_info["locked_until"] and datetime.datetime.now() < user_info["locked_until"]:
                            time_left = (user_info["locked_until"] - datetime.datetime.now()).seconds // 60
                            st.error(f"🔒 Account Locked due to multiple failed attempts. Try again in {time_left + 1} minutes.")
                        else:
                            # Check 2: Password sahi hai ya nahi?
                            if user_info["password_hash"] == hash_password(entered_pass):
                                # Password Sahi - Lock reset karo
                                st.session_state['user_db'][entered_user]["failed_attempts"] = 0
                                st.session_state['user_db'][entered_user]["locked_until"] = None
                                
                                st.session_state['logged_in'] = True
                                st.session_state['username'] = entered_user
                                st.session_state['role'] = user_info["role"]
                                log_action(entered_user, "LOGIN", "User authenticated successfully")
                                st.rerun()
                            else:
                                # Password Galat - Lockout Counter badhao
                                attempts = user_info["failed_attempts"] + 1
                                st.session_state['user_db'][entered_user]["failed_attempts"] = attempts
                                
                                if attempts >= 3:
                                    # 3 baar galat - 5 minute ke liye lock
                                    lock_time = datetime.datetime.now() + datetime.timedelta(minutes=5)
                                    st.session_state['user_db'][entered_user]["locked_until"] = lock_time
                                    log_action(entered_user, "BRUTE_FORCE_ATTEMPT", "Account locked after 3 failed logins")
                                    st.error("🚨 Security Alert: Account Locked! 3 failed attempts. Wait 5 minutes.")
                                else:
                                    st.error(f"❌ Invalid Credentials. Warning: Attempt {attempts}/3")
                    else:
                        st.error("❌ Access Denied: Invalid Credentials")
                        
        with tab2:
            with st.form("register_form"):
                st.subheader("Create New Account")
                new_user = st.text_input("Choose Username")
                new_pass = st.text_input("Choose Password", type="password")
                new_role = st.selectbox("Select Role", ["Analyst", "Admin"]) 
                register_btn = st.form_submit_button("Register User")
                
                if register_btn:
                    if new_user in st.session_state['user_db']:
                        st.warning("⚠️ Username already exists! Try another.")
                    elif len(new_user) == 0 or len(new_pass) == 0:
                        st.warning("⚠️ Username and Password cannot be empty.")
                    else:
                        st.session_state['user_db'][new_user] = {
                            "password_hash": hash_password(new_pass),
                            "role": new_role,
                            "failed_attempts": 0,      # Naye user ke liye default
                            "locked_until": None       # Naye user ke liye default
                        }
                        st.success(f"✅ Success! Account created for '{new_user}'. Please go to Login tab.")

    st.stop() # Script will stop here if not login

# ==========================================
# 📊 PILLAR 2: DASHBOARD 
# ==========================================

# --- Sidebar info ---
st.sidebar.markdown(f"👤 **User:** {st.session_state['username']}")
st.sidebar.markdown(f"🛡️ **Role:** {st.session_state['role']}")

if st.sidebar.button("Logout"):
    st.session_state['logged_in'] = False
    st.session_state['username'] = ''
    st.session_state['role'] = ''
    st.rerun()

st.sidebar.divider()

# --- Data Loading ---
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

# ==========================================
# 🕵️ THREAT DETECTION & RISK SCORING ENGINE
# ==========================================
import datetime

# 1. Result yaad rakhne ke liye Session State
if 'last_scan' not in st.session_state:
    st.session_state['last_scan'] = None

# Aapka AI Risk Scoring Logic
def calculate_risk_score(text):
    text = text.lower()
    score = 10 
    detected_type = "Suspicious Activity"
    
    if any(word in text for word in ["0-day", "exploit", "cve"]):
        score += 80
        detected_type = "Zero-Day Exploit"
    elif any(word in text for word in ["ransom", "encrypt", "bitcoin"]):
        score += 75
        detected_type = "Ransomware"
    elif any(word in text for word in ["database", "leak", "dump", "passwords"]):
        score += 65
        detected_type = "Data Breach"
    elif any(word in text for word in ["login", "fake page", "phish"]):
        score += 45
        detected_type = "Phishing"
    elif any(word in text for word in ["ddos", "botnet", "c2"]):
        score += 35
        detected_type = "Botnet"
        
    if any(word in text for word in ["bank", "government", "military", "hospital"]):
        score += 15 
        
    score = min(score, 100)
    
    if score >= 90:
        severity = "Critical"
    elif score >= 70:
        severity = "High"
    elif score >= 40:
        severity = "Medium"
    else:
        severity = "Low"
        
    return detected_type, severity, score

# Sidebar UI
if st.session_state['role'] in ["Admin", "Analyst"]:
    with st.sidebar.expander("🕵️ Scanner: Detect & Score Threat", expanded=True):
        
        # 2. Agar purana result save hai, toh yahan ruka rahega!
        if st.session_state['last_scan']:
            st.success(f"🚨 Result: {st.session_state['last_scan']['type']}")
            st.warning(f"🔢 Score: {st.session_state['last_scan']['score']}/100 ➔ [{st.session_state['last_scan']['severity']}]")
            
            # Ek chota clear button taaki agla scan kar sakein
            if st.button("Clear Result"):
                st.session_state['last_scan'] = None
                st.rerun()

        st.divider()
        
        with st.form("detect_threat_form"):
            st.write("Paste suspicious Dark Web text to analyze")
            
            suspicious_text = st.text_area("Dark Web Intercept")
            source_input = st.text_input("Source", "Telegram")
            country_input = st.text_input("Target Country", "India")
            
            analyze_btn = st.form_submit_button("Analyze Threat")
            
            if analyze_btn and suspicious_text:
                d_type, d_severity, risk_score = calculate_risk_score(suspicious_text)
                
                new_id = f"T{datetime.datetime.now().strftime('%M%S')}"
                current_date = datetime.datetime.now().strftime('%Y-%m-%d')
                
                new_record = pd.DataFrame([{
                    "threat_id": new_id,
                    "threat_type": d_type,
                    "severity": d_severity,
                    "source": source_input,
                    "country": country_input,
                    "date": current_date,
                    "status": "Active"
                }])
                
                try:
                    updated_data = pd.concat([data, new_record], ignore_index=True)
                    updated_data.to_csv(DATA_FILE, index=False)
                    log_action(st.session_state['username'], "THREAT_ADDED", f"Type: {d_type}, Score: {risk_score}")
                    # 3. Result ko Session State me save kar diya
                    st.session_state['last_scan'] = {
                        'type': d_type,
                        'severity': d_severity,
                        'score': risk_score
                    }
                    
                    st.rerun() # Refresh hoga, charts badlenge, aur score screen par bana rahega!
                except Exception as e:
                    st.error(f"Error saving data: {e}")
# ==========================================

# ==========================================
# 🛡️ INCIDENT RESPONSE (Resolve Threats)
# ==========================================
# Yeh feature bhi Admin aur Analyst dono ke paas hoga
if st.session_state['role'] in ["Admin", "Analyst"]:
    with st.sidebar.expander("🛠️ Action: Resolve Threat"):
        
        # Sirf 'Active' status wale threats dhoondhein
        active_threats = data[data['status'].str.lower() == 'active']
        
        if active_threats.empty:
            st.success("✅ All clear! No active threats right now.")
        else:
            with st.form("resolve_form"):
                st.write("Select a threat to mitigate:")
                
                # Dropdown ke liye ID aur Type ko jod kar dikhana (e.g., T4521 - Phishing)
                options = active_threats['threat_id'].astype(str) + " - " + active_threats['threat_type'].astype(str)
                selected_threat = st.selectbox("Active Threats", options.tolist())
                
                resolve_btn = st.form_submit_button("Mark as Resolved ✅")
                
                if resolve_btn and selected_threat:
                    # ID ko alag nikalna (split karke)
                    threat_id_to_resolve = selected_threat.split(" - ")[0]
                    
                    # Dataframe me status update karna
                    data.loc[data['threat_id'] == threat_id_to_resolve, 'status'] = 'Resolved'
                    
                    try:
                        # CSV me wapas save karna
                        data.to_csv(DATA_FILE, index=False)
                        
                        # Audit Log me record karna!
                        log_action(st.session_state['username'], "THREAT_RESOLVED", f"Resolved Threat ID: {threat_id_to_resolve}")
                        
                        st.success(f"✅ {threat_id_to_resolve} marked as Resolved!")
                        import time
                        time.sleep(2) # 2 second ka pause padhne ke liye
                        st.rerun() 
                    except Exception as e:
                        st.error(f"Error updating file: {e}")
# ==========================================
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
