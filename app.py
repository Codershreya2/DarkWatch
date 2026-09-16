import streamlit as st
import pandas as pd
import plotly.express as px
from supabase import create_client
from datetime import datetime, timedelta
import time
import re
import bcrypt
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Page config
st.set_page_config(page_title="DarkWatch", page_icon="🛡️", layout="wide")

# ==========================================
# HELPER FUNCTIONS (HASHING & EMAIL)
# ==========================================
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def send_otp_email(receiver_email, otp):
    try:
        sender_email = st.secrets["email"]["sender_email"]
        sender_password = st.secrets["email"]["app_password"]
    except Exception as e:
        st.error(f"⚠️ Email secrets error: {e}")
        return False

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "🛡️ DarkWatch - Security OTP"
    msg.attach(MIMEText(f"Your DarkWatch OTP code is: {otp}\nIt is valid for this session only.", 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        st.error(f"❌ Failed to send email: {e}")
        return False

# ==========================================
# DATABASE FUNCTIONS
# ==========================================
@st.cache_resource
def init_supabase():
    url = st.secrets["supabase"]["url"]
    key = st.secrets["supabase"]["key"]
    return create_client(url, key)

@st.cache_data(ttl=60)
def load_threats():
    supabase = init_supabase()
    response = supabase.table("threats").select("*").execute()
    return pd.DataFrame(response.data)

@st.cache_data(ttl=60)
def load_events():
    supabase = init_supabase()
    response = supabase.table("security_events").select("*").execute()
    return pd.DataFrame(response.data)

@st.cache_data(ttl=60)
def load_users():
    supabase = init_supabase()
    response = supabase.table("users").select("*").execute()
    return pd.DataFrame(response.data)

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
    load_threats.clear()

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
    load_events.clear()

def register_user(username, email, password, role="User"):
    supabase = init_supabase()
    users_df = load_users()
    
    if not users_df.empty:
        if username in users_df["username"].values:
            return False, "Username already exists!"
        if "email" in users_df.columns and email in users_df["email"].values:
            return False, "Email already exists!"
    
    hashed_password = hash_password(password)
    
    data = {
        "username": username,
        "email": email,
        "password": hashed_password,
        "role": role,
        "created_at": datetime.now().isoformat()
    }
    
    try:
        supabase.table("users").insert(data).execute()
        return True, "Registration successful! Please login."
    except Exception as e:
        return False, f"Error: {str(e)}"

def verify_credentials(email, password):
    supabase = init_supabase()
    users_df = load_users()

    if users_df.empty or "email" not in users_df.columns:
        return False, "No users found or email column missing!", None, None

    user = users_df[users_df["email"] == email]
    if user.empty:
        return False, "Invalid email or password!", None, None

    stored_hashed_password = user.iloc[0]["password"]
    username = user.iloc[0]["username"]
    role = user.iloc[0]["role"]

    if verify_password(password, stored_hashed_password):
        return True, "Credentials valid!", role, username
    else:
        return False, "Invalid email or password!", None, None

def update_password(username, new_password):
    supabase = init_supabase()
    users_df = load_users()
    user_id = users_df[users_df["username"] == username].iloc[0]["id"]
    
    hashed_password = hash_password(new_password)
    supabase.table("users").update({"password": hashed_password}).eq("id", user_id).execute()
    return True, "Password updated successfully!"

def check_password_strength(password):
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("At least 8 characters")
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Uppercase letter")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Lowercase letter")
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Number")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Special character (!@#$%^&*)")
    
    if score == 5:
        strength = "Strong"
        color = "🟢"
    elif score >= 3:
        strength = "Medium"
        color = "🟡"
    else:
        strength = "Weak"
        color = "🔴"
    
    return strength, color, feedback

def save_feedback(user_id, username, rating, comment=""):
    """Save user feedback to database"""
    try:
        supabase = init_supabase()
        supabase.table("feedback").insert({
            "user_id": user_id,
            "username": username,
            "rating": rating,
            "comment": comment
        }).execute()
        return True
    except Exception as e:
        st.error(f"❌ Failed to save feedback: {e}")
        return False

def log_user_activity(user_id, activity_type, description, threat_score=None, severity=None):
    """Log user activity for history"""
    try:
        supabase = init_supabase()
        data = {
            "user_id": user_id,
            "activity_type": activity_type,
            "description": description
        }
        if threat_score:
            data["threat_score"] = threat_score
        if severity:
            data["severity"] = severity
        
        supabase.table("user_activity").insert(data).execute()
        return True
    except Exception as e:
        st.error(f"❌ Failed to log activity: {e}")
        return False

# ==========================================
# SESSION STATE INITIALIZATION
# ==========================================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "email" not in st.session_state:
    st.session_state.email = ""
if "role" not in st.session_state:
    st.session_state.role = ""
if "show_register" not in st.session_state:
    st.session_state.show_register = False
if "show_forgot_password" not in st.session_state:
    st.session_state.show_forgot_password = False
if "show_profile" not in st.session_state:
    st.session_state.show_profile = False
if "show_admin" not in st.session_state:
    st.session_state.show_admin = False
if "reset_token" not in st.session_state:
    st.session_state.reset_token = None
if "reset_username" not in st.session_state:
    st.session_state.reset_username = None
if "otp_sent" not in st.session_state:
    st.session_state.otp_sent = False
if "generated_otp" not in st.session_state:
    st.session_state.generated_otp = None
if "temp_creds" not in st.session_state:
    st.session_state.temp_creds = None
    
if "show_feedback" not in st.session_state:
    st.session_state.show_feedback = False
if "show_logout_feedback" not in st.session_state:
    st.session_state.show_logout_feedback = False
if "notifications" not in st.session_state:
    st.session_state.notifications = []
    
# ==========================================
# FEEDBACK FORM UI
# ==========================================
if st.session_state.get("show_feedback", False):
    st.title("⭐ Give Your Feedback")
    st.write("We'd love to hear your thoughts about DarkWatch!")
    
    with st.form("feedback_form"):
        rating = st.slider("How would you rate DarkWatch?", 1, 5, 5,
                        help="1 = Very Bad, 5 = Excellent")
        comment = st.text_area("Your suggestions or comments (optional)",
                            height=100,
                            placeholder="Tell us what you liked or what we can improve...")
        
        col1, col2 = st.columns(2)
        with col1:
            submitted = st.form_submit_button("Submit Feedback", use_container_width=True)
        with col2:
            cancel = st.form_submit_button("Cancel", use_container_width=True, type="secondary")
        
        if submitted:
            if save_feedback(st.session_state.user_id, st.session_state.username, rating, comment):
                st.success("✅ Thank you for your valuable feedback!")
                # Add notification
                st.session_state.notifications.append({
                    "message": "Feedback submitted!",
                    "type": "success",
                    "time": datetime.now().strftime("%H:%M:%S")
                })
                st.session_state.show_feedback = False
                time.sleep(2)
                st.rerun()
            else:
                st.error("❌ Failed to submit feedback. Please try again.")
        
        if cancel:
            st.session_state.show_feedback = False
            st.rerun()
    
    st.stop()  # Stop here so main content doesn't load

# ==========================================
# AUTHENTICATION UI (LOGIN/REGISTER)
# ==========================================
if not st.session_state.logged_in:
    st.title("🛡️ DarkWatch - Cybersecurity Dashboard")
    st.markdown("### Secure Login Required")
    
    # --- FORGOT PASSWORD PAGE ---
    if st.session_state.show_forgot_password:
        st.markdown("#### 🔑 Forgot Password")
        st.info("Enter your username to reset password")
        
        if st.session_state.reset_token is None:
            with st.form("forgot_password_form"):
                fp_username = st.text_input("Username")
                submitted = st.form_submit_button("Generate Reset Token")
                
                if submitted:
                    if not fp_username:
                        st.error("❌ Please enter your username!")
                    else:
                        users_df = load_users()
                        if not users_df.empty and fp_username in users_df["username"].values:
                            reset_token = f"reset_{fp_username}_{int(datetime.now().timestamp())}"
                            st.session_state.reset_token = reset_token
                            st.session_state.reset_username = fp_username
                            st.success("✅ Reset token generated!")
                            st.info("💡 Use this token to reset your password:")
                            st.code(reset_token)
                            st.rerun()
                        else:
                            st.error("❌ Username not found!")
        else:
            st.success("✅ Reset token generated!")
            st.code(st.session_state.reset_token)
            
            st.markdown("### Reset Password")
            with st.form("reset_password_form"):
                reset_token_input = st.text_input("Enter Reset Token")
                new_password = st.text_input("New Password", type="password")
                new_password_confirm = st.text_input("Confirm New Password", type="password")
                
                if new_password:
                    strength, color, feedback = check_password_strength(new_password)
                    st.markdown(f"**Password Strength:** {strength} {color}")
                
                submitted_reset = st.form_submit_button("Reset Password")
                
                if submitted_reset:
                    if reset_token_input != st.session_state.reset_token:
                        st.error("❌ Invalid reset token!")
                    elif new_password != new_password_confirm:
                        st.error("❌ Passwords do not match!")
                    elif len(new_password) < 8:
                        st.error("❌ Password must be at least 8 characters!")
                    else:
                        success, message = update_password(st.session_state.reset_username, new_password)
                        if success:
                            st.success("✅ Password reset successful! Please login.")
                            time.sleep(2)
                            st.session_state.show_forgot_password = False
                            st.session_state.reset_token = None
                            st.session_state.reset_username = None
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")
        
        if st.button("← Back to Login"):
            st.session_state.show_forgot_password = False
            st.session_state.reset_token = None
            st.session_state.reset_username = None
            st.rerun()
    
    # --- REGISTRATION PAGE ---
    elif st.session_state.show_register:
        st.markdown("#### 🔐 New User Registration")
        
        if not st.session_state.otp_sent:
            with st.form("register_form"):
                reg_username = st.text_input("Username")
                reg_email = st.text_input("Email Address")
                reg_password = st.text_input("Password", type="password")
                reg_password_confirm = st.text_input("Confirm Password", type="password")
                reg_role = st.selectbox("Role", ["User", "Admin"])
                
                if reg_password:
                    strength, color, feedback = check_password_strength(reg_password)
                    st.markdown(f"**Password Strength:** {strength} {color}")
                
                submitted = st.form_submit_button("Send OTP")
                
                if submitted:
                    if not reg_username or not reg_email or not reg_password:
                        st.error("❌ Please fill all fields!")
                    elif reg_password != reg_password_confirm:
                        st.error("❌ Passwords do not match!")
                    elif len(reg_password) < 8:
                        st.error("❌ Password must be at least 8 characters!")
                    else:
                        users_df = load_users()
                        if not users_df.empty and reg_username in users_df["username"].values:
                            st.error("❌ Username already exists!")
                        elif not users_df.empty and "email" in users_df.columns and reg_email in users_df["email"].values:
                            st.error("❌ Email already registered!")
                        else:
                            otp = str(random.randint(100000, 999999))
                            st.session_state.generated_otp = otp
                            st.session_state.temp_creds = {"user": reg_username, "email": reg_email, "pass": reg_password, "role": reg_role}
                            
                            if send_otp_email(reg_email, otp):
                                st.session_state.otp_sent = True
                                st.success(f"✅ OTP sent to {reg_email}")
                                st.rerun()
                            else:
                                st.error("❌ Failed to send OTP. Check email configuration.")
        else:
            with st.form("verify_register_otp"):
                st.info(f"OTP sent to {st.session_state.temp_creds['email']}")
                entered_otp = st.text_input("Enter 6-digit OTP")
                if st.form_submit_button("Verify & Register"):
                    if entered_otp == st.session_state.generated_otp:
                        creds = st.session_state.temp_creds
                        success, message = register_user(creds["user"], creds["email"], creds["pass"], creds["role"])
                        if success:
                            st.success("✅ " + message)
                            st.session_state.otp_sent = False
                            st.session_state.show_register = False
                            time.sleep(2)
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")
                    else:
                        st.error("❌ Incorrect OTP!")

        if st.button("← Cancel & Back to Login"):
            st.session_state.otp_sent = False
            st.session_state.show_register = False
            st.rerun()
    
    # --- LOGIN PAGE ---
    else:
        if not st.session_state.otp_sent:
            with st.form("login_form"):
                login_email = st.text_input("Email")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Login")
                
                if submitted:
                    if not login_email or not password:
                        st.error("❌ Please fill all fields!")
                    else:
                        success, message, role, username = verify_credentials(login_email, password)
                        if success:
                            otp = str(random.randint(100000, 999999))
                            st.session_state.generated_otp = otp
                            st.session_state.temp_creds = {"email": login_email, "role": role, "user": username}
                            
                            if send_otp_email(login_email, otp):
                                st.session_state.otp_sent = True
                                st.rerun()
                            else:
                                st.error("❌ Failed to send OTP. Check email configuration.")
                        else:
                            st.error(f"❌ {message}")
        else:
            with st.form("verify_login_otp"):
                st.info(f"Enter the OTP sent to {st.session_state.temp_creds['email']}")
                entered_otp = st.text_input("Enter 6-digit OTP")
                
                if st.form_submit_button("Verify OTP"):
                    if entered_otp == st.session_state.generated_otp:
                        st.session_state.logged_in = True
                        st.session_state.username = st.session_state.temp_creds["user"]
                        st.session_state.email = st.session_state.temp_creds["email"]
                        st.session_state.role = st.session_state.temp_creds["role"]
                        st.session_state.otp_sent = False
                        st.rerun()
                    else:
                        st.error("❌ Incorrect OTP!")
            
            if st.button("← Cancel Login"):
                st.session_state.otp_sent = False
                st.rerun()
        
        if not st.session_state.otp_sent:
            st.markdown("---")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🆕 Don't have an account? Register"):
                    st.session_state.show_register = True
                    st.rerun()
            with col2:
                if st.button("🔑 Forgot Password?"):
                    st.session_state.show_forgot_password = True
                    st.rerun()
            
            st.info("🔒 This dashboard requires authentication. Contact admin for access.")
            
    st.stop()

# ==========================================
# DASHBOARD CODE (POST-LOGIN)
# ==========================================
# Sidebar
with st.sidebar:
    st.title("🛡️ DarkWatch")
    st.markdown(f"### 👤 {st.session_state.username}")
    st.write(f"📧 {st.session_state.email}")
    st.markdown(f"**Role:** {st.session_state.role}")
    st.markdown("---")
    
    if st.button("📊 Dashboard"):
        st.session_state.show_profile = False
        st.session_state.show_admin = False
        st.rerun()
    
    if st.button("👤 My Profile"):
        st.session_state.show_profile = True
        st.session_state.show_admin = False
        st.rerun()
    
    if st.session_state.role == "Admin":
        if st.button("👨‍💼 Admin Panel"):
            st.session_state.show_admin = True
            st.session_state.show_profile = False
            st.rerun()
    
    if st.button("🚪 Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.email = ""
        st.session_state.role = ""
        st.session_state.show_profile = False
        st.session_state.show_admin = False
        st.rerun()
        
        # Notifications section
    st.markdown("---")
    st.subheader("🔔 Recent Alerts")
    
    if st.session_state.notifications:
        for notif in st.session_state.notifications[-5:]:
            if notif["type"] == "success":
                st.success(f"⚡ {notif['time']}: {notif['message']}", icon="✅")
            elif notif["type"] == "warning":
                st.warning(f"⚡ {notif['time']}: {notif['message']}", icon="⚠️")
            elif notif["type"] == "error":
                st.error(f"⚡ {notif['time']}: {notif['message']}", icon="❌")
            else:
                st.info(f"⚡ {notif['time']}: {notif['message']}", icon="ℹ️")
    else:
        st.info("No recent alerts")
    
    st.markdown("---")
    
    # Feedback button
    if st.button("⭐ Give Feedback"):
        st.session_state.show_feedback = True
        st.rerun()
    
    auto_refresh = st.checkbox("🔄 Auto-refresh every 30 seconds", value=False)

# Main Content
if not st.session_state.show_profile and not st.session_state.show_admin:
    # Dashboard
    st.title("🛡️ DarkWatch")
    st.subheader("Dark Web Threat Intelligence Dashboard")
    st.write("Monitor, analyze and visualize cybersecurity threat intelligence data.")
    
    try:
        threats_df = load_threats()
        events_df = load_events()
    except Exception as error:
        st.error(f"Database connection error: {error}")
        st.stop()
    
    # Metrics
    metric1, metric2, metric3 = st.columns(3)
    
    with metric1:
        st.metric("Total Threats", len(threats_df) if not threats_df.empty else 0)
    
    with metric2:
        if not threats_df.empty and "severity" in threats_df.columns:
            high_risk = len(threats_df[threats_df["severity"].isin(["Critical", "High"])])
        else:
            high_risk = 0
        st.metric("High Risk Threats", high_risk)
    
    with metric3:
        if not threats_df.empty and "status" in threats_df.columns:
            active_alerts = len(threats_df[threats_df["status"] == "Active"])
        else:
            active_alerts = 0
        st.metric("Active Alerts", active_alerts)
    
    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Analytics", "🔍 Threat Scanner", "🛠️ Manage Threats", "📥 Export"])
    
    # Analytics Tab
    with tab1:
        st.markdown("## Threat Analytics")
        
        if threats_df.empty:
            st.info("No threats found. Add threats from the Manage Threats tab.")
        else:
            chart_col1, chart_col2 = st.columns(2)
            
            with chart_col1:
                if "severity" in threats_df.columns:
                    severity_data = threats_df["severity"].value_counts().reset_index()
                    severity_data.columns = ["Severity", "Count"]
                    fig = px.pie(severity_data, values="Count", names="Severity", title="Threats by Severity")
                    st.plotly_chart(fig, use_container_width=True)
            
            with chart_col2:
                if "target_country" in threats_df.columns:
                    country_data = threats_df["target_country"].value_counts().reset_index()
                    country_data.columns = ["Country", "Count"]
                    fig = px.bar(country_data, x="Country", y="Count", color="Count", title="Threats by Target Country", color_continuous_scale="Reds")
                    st.plotly_chart(fig, use_container_width=True)
            
            if "status" in threats_df.columns:
                status_data = threats_df["status"].value_counts().reset_index()
                status_data.columns = ["Status", "Count"]
                fig = px.funnel(status_data, x="Count", y="Status", title="Threat Status Overview")
                st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("## Security Events Timeline")
        
        if events_df.empty or "timestamp" not in events_df.columns:
            st.info("No security events available.")
        else:
            events_df["timestamp"] = pd.to_datetime(events_df["timestamp"])
            events_df = events_df.sort_values("timestamp")
            fig = px.scatter(events_df, x="timestamp", y="event_type", color="severity", title="Security Events Over Time", color_discrete_map={"Critical": "red", "High": "orange", "Medium": "gold", "Low": "green"})
            st.plotly_chart(fig, use_container_width=True)
    
    # Threat Scanner Tab
    with tab2:
        st.markdown("## 🕵️ Threat Scanner")
        st.info("Paste suspicious dark-web/forum text to estimate its threat severity.")
        
        with st.form("scanner_form"):
            threat_text = st.text_area("Suspicious Text", height=180, placeholder="Paste suspicious text here...")
            analyze_button = st.form_submit_button("Analyze Threat")
        
        if analyze_button:
            if not threat_text.strip():
                st.warning("Please paste some text to analyze.")
            else:
                critical_keywords = ["attack", "breach", "exploit", "zero-day", "ransomware"]
                high_keywords = ["vulnerability", "leak", "stolen", "credentials", "database"]
                medium_keywords = ["suspicious", "malicious", "phishing", "malware"]
                
                score = 0
                text_lower = threat_text.lower()
                
                for keyword in critical_keywords:
                    if keyword in text_lower:
                        score += 3
                
                for keyword in high_keywords:
                    if keyword in text_lower:
                        score += 2
                
                for keyword in medium_keywords:
                    if keyword in text_lower:
                        score += 1
                
                if score >= 10:
                    severity = "Critical"
                    indicator = "🔴"
                elif score >= 6:
                    severity = "High"
                    indicator = "🟠"
                elif score >= 3:
                    severity = "Medium"
                    indicator = "🟡"
                else:
                    severity = "Low"
                    indicator = "🟢"
                
                st.markdown(f"### Threat Score: {score} {indicator}")
                st.markdown(f"**Detected Severity:** {severity}")
                
                if score >= 6:
                    save_event(event_type="Threat Detected", severity=severity, source_ip="Scanner", target="DarkWatch Monitor", status="Investigating")
                    st.success("✅ High-risk threat event saved to database.")
    
    # Manage Threats Tab
    with tab3:
        st.markdown("## 🛠️ Manage Threats")
        
        with st.expander("➕ Add New Threat"):
            with st.form("add_threat_form"):
                form_col1, form_col2 = st.columns(2)
                with form_col1:
                    source = st.text_input("Source")
                    target_country = st.selectbox("Target Country", ["India", "USA", "UK", "Germany", "Japan", "Other"])
                with form_col2:
                    severity = st.selectbox("Severity", ["Critical", "High", "Medium", "Low"])
                    status = st.selectbox("Status", ["Active", "Investigating", "Resolved"])
                description = st.text_area("Threat Description")
                add_threat_button = st.form_submit_button("Add Threat")
            
            if add_threat_button:
                if not source.strip() or not description.strip():
                    st.error("❌ Source and description are required.")
                else:
                    save_threat(source, target_country, severity, status, description)
                    st.success("✅ Threat added successfully.")
                    st.rerun()
        
        st.markdown("## Threat Records")
        
        if threats_df.empty:
            st.info("No threat records available.")
        else:
            filter_col1, filter_col2, filter_col3 = st.columns(3)
            
            with filter_col1:
                severity_filter = st.multiselect("Filter by Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
            
            with filter_col2:
                country_list = threats_df["target_country"].dropna().unique().tolist()
                country_filter = st.multiselect("Filter by Country", country_list, default=country_list)
            
            with filter_col3:
                status_filter = st.multiselect("Filter by Status", ["Active", "Investigating", "Resolved"], default=["Active", "Investigating", "Resolved"])
            
            filtered_threats = threats_df[
                threats_df["severity"].isin(severity_filter) &
                threats_df["target_country"].isin(country_filter) &
                threats_df["status"].isin(status_filter)
            ]
            
            st.dataframe(filtered_threats, use_container_width=True)
    
    # Export Tab
    with tab4:
        st.markdown("## 📥 Export Data")
        
        export_col1, export_col2 = st.columns(2)
        
        with export_col1:
            st.markdown("### Threat Data")
            if threats_df.empty:
                st.info("No threat data available.")
            else:
                threats_csv = threats_df.to_csv(index=False).encode("utf-8")
                st.download_button("Download Threats CSV", data=threats_csv, file_name=f"darkwatch_threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
        
        with export_col2:
            st.markdown("### Security Event Data")
            if events_df.empty:
                st.info("No event data available.")
            else:
                events_csv = events_df.to_csv(index=False).encode("utf-8")
                st.download_button("Download Events CSV", data=events_csv, file_name=f"darkwatch_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
    
    # Auto Refresh
    if auto_refresh:
        time.sleep(30)
        st.rerun()
    
    st.markdown("---")
    st.caption("Built with 💙 by DarkWatch Security Team | Powered by Streamlit + Supabase")

# Profile Page
elif st.session_state.show_profile:
    st.title("👤 My Profile")
    st.markdown(f"**Username:** {st.session_state.username}")
    st.markdown(f"**Email:** {st.session_state.email}")
    st.markdown(f"**Role:** {st.session_state.role}")
    
    st.markdown("### Change Password")
    with st.form("change_password_form"):
        old_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password")
        new_password_confirm = st.text_input("Confirm New Password", type="password")
        
        if new_password:
            strength, color, feedback = check_password_strength(new_password)
            st.markdown(f"**Password Strength:** {strength} {color}")
        
        submitted = st.form_submit_button("Update Password")
        
        if submitted:
            success, message, _, _ = verify_credentials(st.session_state.email, old_password)
            
            if not success:
                st.error("❌ Current password is incorrect!")
            elif new_password != new_password_confirm:
                st.error("❌ New passwords do not match!")
            elif len(new_password) < 8:
                st.error("❌ Password must be at least 8 characters!")
            else:
                success, message = update_password(st.session_state.username, new_password)
                if success:
                    st.success("✅ Password updated successfully!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(f"❌ {message}")

# Admin Panel
elif st.session_state.show_admin:
    if st.session_state.role != "Admin":
        st.error("❌ Access denied. Admins only.")
    else:
        st.title("⚙️ Admin Panel")
        
        tab1, tab2, tab3 = st.tabs(["Manage Threats", "Manage Users", "📊 Feedback"])
        
        with tab1:
            st.subheader("Manage Threats")
            threats_df = load_threats()
            if threats_df.empty:
                st.info("ℹ️ No threats recorded yet.")
            else:
                st.dataframe(threats_df, use_container_width=True, hide_index=True)
                threat_id = st.text_input("Enter Threat ID to delete")
                if st.button("Delete Threat"):
                    if threat_id:
                        supabase = init_supabase()
                        supabase.table("threats").delete().eq("id", threat_id).execute()
                        st.success("✅ Threat deleted!")
                        st.rerun()
        
        with tab2:
            st.subheader("Manage Users")
            users_df = load_users()
            if users_df.empty:
                st.info("ℹ️ No users found.")
            else:
                st.dataframe(users_df, use_container_width=True, hide_index=True)
        
        with tab3:
            st.subheader("⭐ User Feedback")
            
            # Fetch all feedback
            feedback_data = supabase.table("feedback").select("*").order("created_at", desc=True).execute().data
            
            if not feedback_data:
                st.info("ℹ️ No feedback received yet.")
            else:
                feedback_df = pd.DataFrame(feedback_data)
                
                # Average rating
                avg_rating = feedback_df["rating"].mean()
                total_feedback = len(feedback_df)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Average Rating", f"{avg_rating:.1f} ⭐")
                with col2:
                    st.metric("Total Feedback", total_feedback)
                with col3:
                    five_star = len(feedback_df[feedback_df["rating"] == 5])
                    st.metric("5 Star Reviews", five_star)
                
                st.markdown("---")
                
                # Rating distribution chart
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("Rating Distribution")
                    rating_counts = feedback_df["rating"].value_counts().sort_index()
                    fig = px.bar(
                        x=rating_counts.index,
                        y=rating_counts.values,
                        labels={"x": "Rating", "y": "Count"},
                        title="Feedback by Rating",
                        color=rating_counts.values,
                        color_continuous_scale="Blues"
                    )
                    fig.update_layout(showlegend=False)
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    st.subheader("Recent Feedback")
                    st.dataframe(
                        feedback_df[["username", "rating", "comment", "created_at"]].head(10),
                        use_container_width=True,
                        hide_index=True
                    )
                
                st.markdown("---")
                
                # Export button
                csv = feedback_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "📥 Download All Feedback",
                    data=csv,
                    file_name=f"darkwatch_feedback_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )