import streamlit as st
import bcrypt
import pandas as pd
from supabase import create_client, Client

# ---------------------------
# Page Config & Session Init
# ---------------------------
st.set_page_config(
    page_title="DarkWatch",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "role" not in st.session_state:
    st.session_state.role = ""
if "user_id" not in st.session_state:
    st.session_state.user_id = ""

# ---------------------------
# Supabase Init
# ---------------------------
if "supabase" not in st.session_state:
    try:
        supabase_url = st.secrets["supabase"]["url"]
        supabase_key = st.secrets["supabase"]["key"]
        supabase_client: Client = create_client(supabase_url, supabase_key)
        st.session_state.supabase = supabase_client
    except Exception as e:
        st.error(f"❌ Supabase connection failed: {e}")
        st.stop()

supabase: Client = st.session_state.supabase

# ---------------------------
# Helper Functions
# ---------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

def get_user_by_username(username: str):
    response = supabase.table("users").select("*").eq("username", username).execute()
    return response.data[0] if response.data else None

def save_event(event_type: str, severity: str, source_ip: str, target: str, status: str):
    supabase.table("security_events").insert({
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "target": target,
        "status": status
    }).execute()

def analyze_threat_text(threat_text):
    text = threat_text.lower()
    
    critical_keywords = ["attack", "breach", "exploit", "zero-day", "ransomware"]
    high_keywords = ["vulnerability", "leak", "stolen", "credentials", "database"]
    medium_keywords = ["suspicious", "malicious", "phishing", "malware"]
    
    score = 0
    detected_indicators = []
    
    for keyword in critical_keywords:
        if keyword in text:
            score += 3
            detected_indicators.append(f"{keyword} (+3)")
    
    for keyword in high_keywords:
        if keyword in text:
            score += 2
            detected_indicators.append(f"{keyword} (+2)")
    
    for keyword in medium_keywords:
        if keyword in text:
            score += 1
            detected_indicators.append(f"{keyword} (+1)")
    
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
    
    return score, severity, color, detected_indicators

# ---------------------------
# Sidebar
# ---------------------------
with st.sidebar:
    st.title("🛡️ DarkWatch")
    
    if st.session_state.logged_in:
        st.write(f"👤 **User:** {st.session_state.username}")
        st.write(f"🔐 **Role:** {st.session_state.role}")
        
        if st.button("🚪 Logout"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.session_state.logged_in = False
            st.rerun()
        
        st.divider()
        page = st.radio(
            "📋 Navigation",
            ["Dashboard", "Threat Scanner", "Security Events", "Analytics", "Profile", "Admin Panel"]
            if st.session_state.role == "admin"
            else ["Dashboard", "Threat Scanner", "Security Events", "Analytics", "Profile"],
            label_visibility="collapsed"
        )
    else:
        page = st.radio(
            "📋 Navigation",
            ["Login", "Register"],
            label_visibility="collapsed"
        )

# ---------------------------
# Pages
# ---------------------------
if not st.session_state.logged_in:
    if page == "Register":
        st.title("📝 Register - DarkWatch")
        
        with st.form("register_form", clear_on_submit=False):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            submit = st.form_submit_button("Register")
        
        if submit:
            if not username or not password:
                st.error("❌ All fields are required.")
            elif password != confirm_password:
                st.error("❌ Passwords do not match.")
            elif len(password) < 6:
                st.error("❌ Password must be at least 6 characters.")
            else:
                existing_user = get_user_by_username(username)
                if existing_user:
                    st.error("❌ Username already exists.")
                else:
                    hashed_pw = hash_password(password)
                    try:
                        supabase.table("users").insert({
                            "username": username,
                            "password": hashed_pw,
                            "role": "user"
                        }).execute()
                        st.success("✅ Registration successful! Please login.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Registration failed: {e}")
    
    elif page == "Login":
        st.title("🔐 Login - DarkWatch")
        
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")
        
        if submit:
            user = get_user_by_username(username)
            if not user:
                st.error("❌ Invalid username or password.")
            elif not verify_password(password, user["password"]):
                st.error("❌ Invalid username or password.")
            else:
                st.session_state.logged_in = True
                st.session_state.username = user["username"]
                st.session_state.role = user["role"]
                st.session_state.user_id = user["id"]
                st.success("✅ Login successful!")
                st.rerun()

else:
    if page == "Dashboard":
        st.title("📊 Dashboard - DarkWatch")
        
        events = supabase.table("security_events").select("*").execute().data or []
        df = pd.DataFrame(events)
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Events", len(df))
        with col2:
            critical_count = len(df[df["severity"] == "Critical"]) if not df.empty else 0
            st.metric("Critical", critical_count, delta_color="inverse")
        with col3:
            high_count = len(df[df["severity"] == "High"]) if not df.empty else 0
            st.metric("High", high_count, delta_color="inverse")
        with col4:
            investigating = len(df[df["status"] == "Investigating"]) if not df.empty else 0
            st.metric("Investigating", investigating)
        
        if not df.empty:
            st.subheader("Recent Events")
            st.dataframe(
                df.sort_values("created_at", ascending=False).head(10)[
                    ["event_type", "severity", "source_ip", "target", "status", "created_at"]
                ] if "created_at" in df.columns else
                df.head(10)[["event_type", "severity", "source_ip", "target", "status"]],
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("ℹ️ No security events recorded yet.")
    
    elif page == "Threat Scanner":
        st.title("🔍 Threat Scanner - DarkWatch")
        
        threat_text = st.text_area(
            "Paste threat intelligence text here",
            height=200,
            placeholder="Example: A suspicious phishing email targeting our database..."
        )
        
        if st.button("Analyze"):
            if not threat_text.strip():
                st.warning("⚠️ Please paste some text to analyze.")
            else:
                score, severity, color, detected_indicators = analyze_threat_text(threat_text)
                
                st.markdown(f"### Threat Score: {score} {color}")
                st.markdown(f"### Severity: {severity}")
                
                if detected_indicators:
                    st.markdown("#### Detected Risk Indicators")
                    for indicator in detected_indicators:
                        st.write(f"• {indicator}")
                else:
                    st.info("ℹ️ No known risk indicators were detected in this text.")
                
                if severity in ["High", "Critical"]:
                    save_event(
                        event_type="Threat Detected",
                        severity=severity,
                        source_ip="Threat Scanner",
                        target="DarkWatch Monitor",
                        status="Investigating"
                    )
                    st.success("✅ High-risk threat event has been logged in Security Events.")
    
    elif page == "Security Events":
        st.title("🚨 Security Events - DarkWatch")
        
        events = supabase.table("security_events").select("*").order("created_at", desc=True).execute().data or [] if "created_at" in pd.DataFrame(supabase.table("security_events").select("*").execute().data or []).columns else supabase.table("security_events").select("*").execute().data or []
        df = pd.DataFrame(events)
        
        if df.empty:
            st.info("ℹ️ No security events recorded yet.")
        else:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=df["severity"].unique(),
                default=df["severity"].unique()
            )
            
            filtered_df = df[df["severity"].isin(severity_filter)]
            
            display_cols = ["event_type", "severity", "source_ip", "target", "status"]
            if "created_at" in df.columns:
                display_cols.append("created_at")
            
            st.dataframe(
                filtered_df[display_cols],
                use_container_width=True,
                hide_index=True
            )
            
            csv = filtered_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Download CSV",
                csv,
                "security_events.csv",
                "text/csv",
                key="download-csv"
            )
    
    elif page == "Analytics":
        st.title("📈 Analytics - DarkWatch")
        
        events = supabase.table("security_events").select("*").execute().data or []
        df = pd.DataFrame(events)
        
        if df.empty:
            st.info("ℹ️ No security events recorded yet.")
        else:
            col1, col2 = st.columns(2)
            
            with col1:
                severity_counts = df["severity"].value_counts()
                st.subheader("Events by Severity")
                st.bar_chart(severity_counts)
            
            with col2:
                status_counts = df["status"].value_counts()
                st.subheader("Events by Status")
                st.bar_chart(status_counts)
    
    elif page == "Profile":
        st.title("👤 Profile - DarkWatch")
        
        user = get_user_by_username(st.session_state.username)
        
        st.write(f"**Username:** {user['username']}")
        st.write(f"**Role:** {user['role']}")
        
        with st.form("update_profile", clear_on_submit=False):
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")
            submit = st.form_submit_button("Update Password")
        
        if submit:
            if new_password:
                if new_password != confirm_password:
                    st.error("❌ Passwords do not match.")
                elif len(new_password) < 6:
                    st.error("❌ Password must be at least 6 characters.")
                else:
                    new_hashed = hash_password(new_password)
                    supabase.table("users").update({"password": new_hashed}).eq("id", user["id"]).execute()
                    st.success("✅ Password updated!")
                    st.rerun()
    
    elif page == "Admin Panel":
        if st.session_state.role != "admin":
            st.error("❌ Access denied. Admins only.")
        else:
            st.title("⚙️ Admin Panel - DarkWatch")
            
            tab1, tab2 = st.tabs(["Manage Threats", "Manage Users"])
            
            with tab1:
                st.subheader("Manage Threats")
                threats = supabase.table("security_events").select("*").execute().data or []
                df = pd.DataFrame(threats)
                
                if df.empty:
                    st.info("ℹ️ No threats recorded yet.")
                else:
                    st.dataframe(df, use_container_width=True, hide_index=True)
                    
                    threat_id = st.text_input("Enter Threat ID to delete")
                    if st.button("Delete Threat"):
                        if threat_id:
                            supabase.table("security_events").delete().eq("id", threat_id).execute()
                            st.success("✅ Threat deleted!")
                            st.rerun()
            
            with tab2:
                st.subheader("Manage Users")
                users = supabase.table("users").select("*").execute().data or []
                users_df = pd.DataFrame(users)
                
                if users_df.empty:
                    st.info("ℹ️ No users found.")
                else:
                    st.dataframe(users_df, use_container_width=True, hide_index=True)