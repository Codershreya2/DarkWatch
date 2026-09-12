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
    # Secrets se email aur password lena (Hardcode mat karna)
    try:
        sender_email = st.secrets["email"]["sender_email"]
        sender_password = st.secrets["email"]["app_password"]
    except Exception:
        st.error("⚠️ Email secrets not configured in .streamlit/secrets.toml!")
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
        st.error(f"Failed to send email: {e}")
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

def register_user(username, email, password, role="User"):
    supabase = init_supabase()
    users_df = load_users()
    
    # Check if username or email already exists
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

def update_profile(username, new_username):
    supabase = init_supabase()
    users_df = load_users()
    user_id = users_df[users_df["username"] == username].iloc[0]["id"]
    
    if not users_df.empty and new_username in users_df["username"].values:
        return False, "Username already exists!"
    
    supabase.table("users").update({"username": new_username}).eq("id", user_id).execute()
    return True, "Profile updated successfully!"

def delete_user(user_id):
    supabase = init_supabase()
    supabase.table("users").delete().eq("id", user_id).execute()
    return True, "User deleted successfully!"

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

# ==========================================
# SESSION STATE INITIALIZATION
# ==========================================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
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

# OTP State Variables
if "otp_sent" not in st.session_state:
    st.session_state.otp_sent = False
if "generated_otp" not in st.session_state:
    st.session_state.generated_otp = None
if "temp_creds" not in st.session_state:
    st.session_state.temp_creds = None

# ==========================================
# AUTHENTICATION UI (LOGIN/REGISTER)
# ==========================================
if not st.session_state.logged_in:
    st.title("🛡️ DarkWatch - Cybersecurity Dashboard")
    st.write("Loaded Secrets:", list(st.secrets.keys()))
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
                        # Check database before sending OTP
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
                            st.error(f"❌ {message}")
        else:
            with st.form("verify_login_otp"):
                st.info(f"Enter the OTP sent to {st.session_state.temp_creds['email']}")
                entered_otp = st.text_input("Enter 6-digit OTP")
                
                if st.form_submit_button("Verify OTP"):
                    if entered_otp == st.session_state.generated_otp:
                        st.session_state.logged_in = True
                        st.session_state.username = st.session_state.temp_creds["user"]
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
else:
    # --- PROFILE PAGE ---
    if st.session_state.show_profile:
        st.title("👤 My Profile")
        
        st.markdown(f"**Username:** {st.session_state.username}")
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
                # We need email to verify current password now. Get it from DB.
                users_df = load_users()
                user_email = users_df[users_df["username"] == st.session_state.username].iloc[0]["email"]
                
                success, message, _, _ = verify_credentials(user_email, old_password)
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
                        st.session_state.show_profile = False
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
        
        st.markdown("### Change Username")
        with st.form("change_username_form"):
            new_username = st.text_input("New Username")
            submitted = st.form_submit_button("Update Username")
            
            if submitted:
                if not new_username:
                    st.error("❌ Please enter a username!")
                else:
                    success, message = update_profile(st.session_state.username, new_username)
                    if success:
                        st.success(f"✅ {message}")
                        st.session_state.username = new_username
                        time.sleep(1)
                        st.session_state.show_profile = False
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
        
        if st.button("← Back to Dashboard"):
            st.session_state.show_profile = False
            st.rerun()
        
        st.stop()
    
    # --- ADMIN PANEL ---
    elif st.session_state.show_admin and st.session_state.role == "Admin":
        st.title("👨‍💼 Admin Panel")
        
        users_df = load_users()
        
        if users_df.empty:
            st.info("📭 No users found!")
        else:
            st.markdown("### Manage Users")
            # Added Email to display
            display_columns = ["id", "username", "role", "created_at"]
            if "email" in users_df.columns:
                display_columns.insert(2, "email")
            
            display_df = users_df[display_columns].copy()
            st.dataframe(display_df, use_container_width=True)
            
            st.markdown("### Delete User")
            with st.form("delete_user_form"):
                user_to_delete = st.selectbox("Select User", users_df["username"].tolist())
                submitted = st.form_submit_button("Delete User")
                
                if submitted:
                    user_id = users_df[users_df["username"] == user_to_delete].iloc[0]["id"]
                    if user_to_delete == st.session_state.username:
                        st.error("❌ Cannot delete yourself!")
                    else:
                        delete_user(user_id)
                        st.success(f"✅ User '{user_to_delete}' deleted successfully!")
                        time.sleep(1)
                        st.rerun()
        
        if st.button("← Back to Dashboard"):
            st.session_state.show_admin = False
            st.rerun()
        
        st.stop()
    
    # --- MAIN DASHBOARD ---
    st.sidebar.title(f"👤 {st.session_state.username}")
    st.sidebar.markdown(f"🛡️ **Role:** {st.session_state.role}")
    st.sidebar.markdown("---")
    
    if st.sidebar.button("📊 Dashboard"):
        st.session_state.show_profile = False
        st.session_state.show_admin = False
        st.rerun()
    
    if st.sidebar.button("👤 Profile"):
        st.session_state.show_profile = True
        st.session_state.show_admin = False
        st.rerun()
    
    if st.session_state.role == "Admin":
        if st.sidebar.button("👨‍💼 Admin Panel"):
            st.session_state.show_admin = True
            st.session_state.show_profile = False
            st.rerun()
    
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.role = ""
        st.session_state.show_profile = False
        st.session_state.show_admin = False
        st.rerun()
    
    auto_refresh = st.sidebar.checkbox("🔄 Auto-refresh (30s)", value=True)
    
    st.title("🛡️ DarkWatch")
    st.subheader("Dark Web Threat Intelligence Dashboard")
    st.markdown("Monitor, analyze and visualize cyber threat intelligence data.")
    
    try:
        threats_df = load_threats()
        events_df = load_events()
    except Exception as e:
        st.error(f"Database connection error: {e}")
        st.info("Make sure Supabase credentials are set in .streamlit/secrets.toml")
        st.stop()
    
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
    
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Analytics", "🔍 Threat Scanner", "🛠️ Manage Threats", "📥 Export"])
    
    with tab1:
        st.markdown("### Threat Analytics")
        
        if threats_df.empty:
            st.info("📭 No threats in database yet. Add some threats using the 'Manage Threats' tab!")
        else:
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
            
            if "status" in threats_df.columns:
                status_dist = threats_df["status"].value_counts().reset_index()
                status_dist.columns = ["Status", "Count"]
                fig = px.funnel(status_dist, x="Count", y="Status", 
                               title="Threat Status Funnel")
                st.plotly_chart(fig, use_container_width=True)
            
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
    
    if auto_refresh:
        time.sleep(30)
        st.rerun()
    
    st.markdown("---")
    st.markdown("Built with ❤️ using Streamlit + Supabase | DarkWatch Security Team")
