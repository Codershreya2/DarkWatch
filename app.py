import streamlit as st
import pandas as pd
import plotly.express as px
from supabase import create_client
from datetime import datetime, timedelta
import time

# Page config
st.set_page_config(page_title="DarkWatch", page_icon="🛡️", layout="wide")

# Initialize Supabase client with caching
@st.cache_resource
def init_supabase():
    url = st.secrets["supabase"]["url"]
    key = st.secrets["supabase"]["key"]
    return create_client(url, key)

# Load threats from database with caching
@st.cache_data(ttl=60)
def load_threats():
    supabase = init_supabase()
    response = supabase.table("threats").select("*").execute()
    return pd.DataFrame(response.data)

# Load security events from database with caching
@st.cache_data(ttl=60)
def load_events():
    supabase = init_supabase()
    response = supabase.table("security_events").select("*").execute()
    return pd.DataFrame(response.data)

# Save new threat to database
def save_threat(source, target_country, severity, status, description):
    supabase = init_supabase()
    data = {
        "source": source,
        "target_country": target_country,
        "severity": severity,
        "status": status,
        "description": description,
        "created_at": datetime.now().isoformat()
    }
    supabase.table("threats").insert(data).execute()

# Save security event to database
def save_event(event_type, severity, source_ip, target, status):
    supabase = init_supabase()
    data = {
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "target": target,
        "status": status,
        "timestamp": datetime.now().isoformat()
    }
    supabase.table("security_events").insert(data).execute()

# Authentication
def check_login(username, password):
    return (
        username == st.secrets["auth"]["admin_username"] and
        password == st.secrets["auth"]["admin_password"]
    )

# Initialize session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "role" not in st.session_state:
    st.session_state.role = ""

# Login Page
if not st.session_state.logged_in:
    st.title("🛡️ DarkWatch - Cybersecurity Dashboard")
    st.markdown("### Secure Login Required")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            if check_login(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.role = "Admin"
                st.rerun()
            else:
                st.error("Invalid credentials!")
    
    st.markdown("---")
    st.info("🔒 This dashboard requires authentication. Contact admin for access.")
    st.stop()

# Main Dashboard (after login)
st.sidebar.title(f"👤 {st.session_state.username}")
st.sidebar.markdown(f"🛡️ **Role:** {st.session_state.role}")
st.sidebar.markdown("---")

if st.sidebar.button("Logout"):
    st.session_state.logged_in = False
    st.rerun()

# Auto-refresh toggle
auto_refresh = st.sidebar.checkbox("🔄 Auto-refresh (30s)", value=True)

# Main content
st.title("🛡️ DarkWatch")
st.subheader("Dark Web Threat Intelligence Dashboard")
st.markdown("Monitor, analyze and visualize cyber threat intelligence data.")

# Load data
try:
    threats_df = load_threats()
    events_df = load_events()
except Exception as e:
    st.error(f"Database connection error: {e}")
    st.info("Make sure Supabase credentials are set in .streamlit/secrets.toml")
    st.stop()

# Metrics - SAFE VERSION (handles empty data)
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total Threats", len(threats_df) if not threats_df.empty else 0)
with col2:
    if not threats_df.empty and "severity" in threats_df.columns:
        high_risk = len(threats_df[threats_df["severity"].isin(["Critical", "High"])])
    else:
        high_risk = 0
    st.metric("High Risk Threats", high_risk)
with col3:
    if not threats_df.empty and "status" in threats_df.columns:
        active = len(threats_df[threats_df["status"] == "Active"])
    else:
        active = 0
    st.metric("Active Alerts", active)

# Tabs
tab1, tab2, tab3, tab4 = st.tabs(["📊 Analytics", "🔍 Threat Scanner", "🛠️ Manage Threats", "📥 Export"])

with tab1:
    st.markdown("### Threat Analytics")
    
    if threats_df.empty:
        st.info("📭 No threats in database yet. Add some threats using the 'Manage Threats' tab!")
    else:
        # Severity distribution
        col1, col2 = st.columns(2)
        with col1:
            if "severity" in threats_df.columns:
                severity_dist = threats_df["severity"].value_counts().reset_index()
                severity_dist.columns = ["Severity", "Count"]
                fig = px.pie(severity_dist, values="Count", names="Severity", 
                            title="Threats by Severity", 
                            color_discrete_sequence=px.colors.qualitative.Set2)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("⚠️ 'severity' column not found in database")
        
        with col2:
            if "target_country" in threats_df.columns:
                country_dist = threats_df["target_country"].value_counts().reset_index()
                country_dist.columns = ["Country", "Count"]
                fig = px.bar(country_dist, x="Country", y="Count", 
                            title="Threats by Target Country",
                            color="Count", color_continuous_scale="Reds")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("⚠️ 'target_country' column not found in database")
        
        # Status distribution
        if "status" in threats_df.columns:
            status_dist = threats_df["status"].value_counts().reset_index()
            status_dist.columns = ["Status", "Count"]
            fig = px.funnel(status_dist, x="Count", y="Status", 
                           title="Threat Status Funnel")
            st.plotly_chart(fig, use_container_width=True)
        
        # Security Events Timeline
        st.markdown("### Security Events Timeline")
        if not events_df.empty and "timestamp" in events_df.columns:
            events_df["timestamp"] = pd.to_datetime(events_df["timestamp"])
            events_timeline = events_df.sort_values("timestamp")
            fig = px.scatter(events_timeline, x="timestamp", y="event_type",
                            color="severity", size=[10]*len(events_timeline),
                            title="Security Events Over Time",
                            color_discrete_map={
                                "Critical": "red",
                                "High": "orange",
                                "Medium": "yellow",
                                "Low": "green"
                            })
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("📭 No security events in database yet.")

with tab2:
    st.markdown("### 🕵️ Threat Scanner")
    st.info("Paste suspicious Dark Web text to analyze threat level")
    
    with st.form("scanner_form"):
        threat_text = st.text_area("Suspicious Text", height=150,
                                  placeholder="Paste text from Dark Web forums, paste sites, etc.")
        submitted = st.form_submit_button("Analyze Threat")
        
        if submitted and threat_text:
            # Simple keyword-based scoring
            critical_keywords = ["attack", "breach", "exploit", "zero-day", "ransomware"]
            high_keywords = ["vulnerability", "leak", "stolen", "credentials", "database"]
            medium_keywords = ["suspicious", "malicious", "phishing", "malware"]
            
            score = 0
            text_lower = threat_text.lower()
            
            for kw in critical_keywords:
                if kw in text_lower:
                    score += 3
            for kw in high_keywords:
                if kw in text_lower:
                    score += 2
            for kw in medium_keywords:
                if kw in text_lower:
                    score += 1
            
            # Determine severity
            if score >= 10:
                severity = "Critical"
                color = "🔴"
            elif score >= 6:
                severity = "High"
                color = "🟠"
            elif score >= 3:
                severity = "Medium"
                color = "🟡"
            else:
                severity = "Low"
                color = "🟢"
            
            st.markdown(f"### Threat Score: {score}/15 {color}")
            st.markdown(f"**Severity:** {severity}")
            
            # Save to database
            if score >= 6:
                save_event(
                    event_type="Threat Detected",
                    severity=severity,
                    source_ip="Scanner",
                    target="Dark Web Monitor",
                    status="Investigating"
                )
                st.success("✅ Threat logged to database!")

with tab3:
    st.markdown("### 🛠️ Manage Threats")
    
    with st.expander("➕ Add New Threat", expanded=False):
        with st.form("add_threat_form"):
            col1, col2 = st.columns(2)
            with col1:
                source = st.text_input("Source (e.g., Forum, Paste Site)")
                target_country = st.selectbox("Target Country", 
                                             ["USA", "UK", "India", "Germany", "Japan", "Other"])
            with col2:
                severity = st.selectbox("Severity", ["Critical", "High", "Medium", "Low"])
                status = st.selectbox("Status", ["Active", "Investigating", "Resolved"])
            description = st.text_area("Description")
            
            submitted = st.form_submit_button("Add Threat")
            if submitted:
                save_threat(source, target_country, severity, status, description)
                st.success("✅ Threat added to database!")
                time.sleep(1)
                st.rerun()
    
    st.markdown("### Filter Threat Records")
    
    if threats_df.empty:
        st.info("📭 No threats in database yet. Add some above!")
    else:
        col1, col2, col3 = st.columns(3)
        with col1:
            severity_filter = st.multiselect("Severity", 
                                            ["Critical", "High", "Medium", "Low"],
                                            default=["Critical", "High", "Medium", "Low"])
        with col2:
            if "target_country" in threats_df.columns:
                country_options = threats_df["target_country"].unique().tolist()
            else:
                country_options = []
            country_filter = st.multiselect("Country", country_options, default=country_options)
        with col3:
            status_filter = st.multiselect("Status",
                                          ["Active", "Investigating", "Resolved"],
                                          default=["Active", "Investigating", "Resolved"])
        
        # Apply filters
        if not threats_df.empty and "severity" in threats_df.columns and "target_country" in threats_df.columns and "status" in threats_df.columns:
            filtered = threats_df[
                threats_df["severity"].isin(severity_filter) &
                threats_df["target_country"].isin(country_filter) &
                threats_df["status"].isin(status_filter)
            ]
            st.dataframe(filtered, use_container_width=True)
        else:
            st.warning("⚠️ Some columns missing in database")

with tab4:
    st.markdown("### 📥 Export Data")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Export Threats")
        if not threats_df.empty:
            csv_threats = threats_df.to_csv(index=False)
            st.download_button(
                label="📥 Download Threats CSV",
                data=csv_threats,
                file_name=f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        else:
            st.info("📭 No data to export")
    
    with col2:
        st.markdown("#### Export Security Events")
        if not events_df.empty:
            csv_events = events_df.to_csv(index=False)
            st.download_button(
                label="📥 Download Events CSV",
                data=csv_events,
                file_name=f"events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        else:
            st.info("📭 No data to export")
    
    st.markdown("---")
    st.info("💡 Data is exported in real-time from the database. Refresh to get latest data.")

# Auto-refresh logic
if auto_refresh:
    time.sleep(30)
    st.rerun()

# Footer
st.markdown("---")
st.markdown("Built with ❤️ using Streamlit + Supabase | DarkWatch Security Team")