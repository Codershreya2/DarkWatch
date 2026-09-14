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
    # Sidebar
    with st.sidebar:
        st.title("🛡️ DarkWatch")
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
            if st.session_state.role == "Admin"
            else ["Dashboard", "Threat Scanner", "Security Events", "Analytics", "Profile"],
            label_visibility="collapsed"
        )
    
    # Dashboard
    if page == "Dashboard":
        st.title("📊 Dashboard")
        threats_df = load_threats()
        events_df = load_events()
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Threats", len(threats_df))
        with col2:
            critical = len(threats_df[threats_df["severity"] == "Critical"]) if not threats_df.empty else 0
            st.metric("Critical Threats", critical)
        with col3:
            st.metric("Security Events", len(events_df))
        
        if not threats_df.empty:
            st.subheader("Recent Threats")
            st.dataframe(threats_df, use_container_width=True, hide_index=True)
        else:
            st.info("ℹ️ No threats recorded yet.")
    
    # Threat Scanner
    elif page == "Threat Scanner":
        st.title("🔍 Threat Scanner")
        
        threat_text = st.text_area("Paste threat intelligence text here", height=200)
        
        if st.button("Analyze"):
            if not threat_text.strip():
                st.warning("⚠️ Please paste some text to analyze.")
            else:
                text = threat_text.lower()
                critical_keywords = ["attack", "breach", "exploit", "zero-day", "ransomware"]
                high_keywords = ["vulnerability", "leak", "stolen", "credentials", "database"]
                medium_keywords = ["suspicious", "malicious", "phishing", "malware"]
                
                score = 0
                detected = []
                
                for kw in critical_keywords:
                    if kw in text:
                        score += 3
                        detected.append(f"{kw} (+3)")
                
                for kw in high_keywords:
                    if kw in text:
                        score += 2
                        detected.append(f"{kw} (+2)")
                
                for kw in medium_keywords:
                    if kw in text:
                        score += 1
                        detected.append(f"{kw} (+1)")
                
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
                
                st.markdown(f"### Threat Score: {score} {color}")
                st.markdown(f"### Severity: {severity}")
                
                if detected:
                    st.markdown("#### Detected Risk Indicators")
                    for item in detected:
                        st.write(f"• {item}")
                else:
                    st.info("ℹ️ No known risk indicators detected.")
                
                if severity in ["High", "Critical"]:
                    save_event("Threat Detected", severity, "Threat Scanner", "DarkWatch Monitor", "Investigating")
                    st.success("✅ High-risk threat logged in Security Events.")
    
    # Security Events
    elif page == "Security Events":
        st.title("🚨 Security Events")
        events_df = load_events()
        
        if events_df.empty:
            st.info("ℹ️ No security events recorded yet.")
        else:
            severity_filter = st.multiselect("Filter by Severity", options=events_df["severity"].unique(), default=events_df["severity"].unique())
            filtered_df = events_df[events_df["severity"].isin(severity_filter)]
            st.dataframe(filtered_df, use_container_width=True, hide_index=True)
            
            csv = filtered_df.to_csv(index=False).encode("utf-8")
            st.download_button("📥 Download CSV", csv, "security_events.csv", "text/csv", key="download-csv")
    
    # Analytics
    elif page == "Analytics":
        st.title("📈 Analytics")
        events_df = load_events()
        
        if events_df.empty:
            st.info("ℹ️ No security events recorded yet.")
        else:
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Events by Severity")
                st.bar_chart(events_df["severity"].value_counts())
            with col2:
                st.subheader("Events by Status")
                st.bar_chart(events_df["status"].value_counts())
    
    # Profile
    elif page == "Profile":
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
    
    # Admin Panel
    elif page == "Admin Panel":
        if st.session_state.role != "Admin":
            st.error("❌ Access denied. Admins only.")
        else:
            st.title("⚙️ Admin Panel")
            
            tab1, tab2 = st.tabs(["Manage Threats", "Manage Users"])
            
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