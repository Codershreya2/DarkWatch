import streamlit as st
import pandas as pd
import plotly.express as px
from supabase import create_client
from datetime import datetime, timedelta
import time
import re

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

# Sign up new user with email
def sign_up_user(email, password, role="User"):
    supabase = init_supabase()
    try:
        response = supabase.auth.sign_up({
            "email": email,
            "password": password
        })
        
        if response.user:
            supabase.auth.update_user({
                "data": {"role": role}
            })
            return True, "Registration successful! Please check your email to verify."
        else:
            return False, "Registration failed!"
    except Exception as e:
        return False, f"Error: {str(e)}"

# Sign in user with email
def sign_in_user(email, password):
    supabase = init_supabase()
    try:
        response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        
        if response.user:
            role = response.user.user_metadata.get("role", "User")
            return True, "Login successful!", role
        else:
            return False, "Login failed!", None
    except Exception as e:
        return False, f"Error: {str(e)}", None

# Send password reset email
def send_reset_email(email):
    supabase = init_supabase()
    try:
        response = supabase.auth.reset_password_for_email(email, {
            "redirect_to": "http://localhost:8501"
        })
        return True, "Reset email sent! Check your inbox."
    except Exception as e:
        return False, f"Error: {str(e)}"

# Update password
def update_user_password(new_password):
    supabase = init_supabase()
    try:
        response = supabase.auth.update_user({
            "password": new_password
        })
        return True, "Password updated successfully!"
    except Exception as e:
        return False, f"Error: {str(e)}"

# Sign out user
def sign_out_user():
    supabase = init_supabase()
    supabase.auth.sign_out()

# Load user profile
def get_user_profile():
    supabase = init_supabase()
    try:
        user = supabase.auth.get_user().user
        if user:
            return user.email, user.user_metadata.get("role", "User")
        return None, None
    except:
        return None, None

# Password strength checker
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

# Initialize session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
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
if "reset_email" not in st.session_state:
    st.session_state.reset_email = None

# Check if user is already logged in
if not st.session_state.logged_in:
    email, role = get_user_profile()
    if email:
        st.session_state.logged_in = True
        st.session_state.email = email
        st.session_state.role = role

# ✅ LOGIN/REGISTER PAGE
if not st.session_state.logged_in:
    st.title("🛡️ DarkWatch - Cybersecurity Dashboard")
    st.markdown("### Secure Login Required")
    
    # Forgot Password Page
    if st.session_state.show_forgot_password:
        st.markdown("#### 🔑 Forgot Password")
        st.info("Enter your email to reset password")
        
        # Check if reset token is already generated
        if st.session_state.reset_token is None:
            with st.form("forgot_password_form"):
                fp_email = st.text_input("Email")
                submitted = st.form_submit_button("Send Reset Link")
                
                if submitted:
                    if not fp_email:
                        st.error("❌ Please enter your email!")
                    elif "@" not in fp_email:
                        st.error("❌ Please enter a valid email!")
                    else:
                        # Generate reset token
                        reset_token = f"reset_{fp_email}_{int(datetime.now().timestamp())}"
                        st.session_state.reset_token = reset_token
                        st.session_state.reset_email = fp_email
                        
                        st.success("✅ Reset link generated!")
                        st.info("💡 For demo purposes, use this token:")
                        st.code(reset_token)
                        st.rerun()
        else:
            # Show reset form (separate from first form)
            st.success("✅ Reset token generated!")
            st.info("💡 Use this token to reset your password:")
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
                        success, message = update_user_password(new_password)
                        if success:
                            st.success("✅ Password reset successful! Please login.")
                            time.sleep(2)
                            st.session_state.show_forgot_password = False
                            st.session_state.reset_token = None
                            st.session_state.reset_email = None
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")
        
        if st.button("← Back to Login"):
            st.session_state.show_forgot_password = False
            st.session_state.reset_token = None
            st.session_state.reset_email = None
            st.rerun()
    
    # Registration Page
    elif st.session_state.show_register:
        st.markdown("#### 🔐 New User Registration")
        
        with st.form("register_form"):
            reg_email = st.text_input("Email")
            reg_password = st.text_input("Password", type="password")
            reg_password_confirm = st.text_input("Confirm Password", type="password")
            reg_role = st.selectbox("Role", ["User", "Admin"])
            
            if reg_password:
                strength, color, feedback = check_password_strength(reg_password)
                st.markdown(f"**Password Strength:** {strength} {color}")
                
                if feedback:
                    st.markdown("**Missing:** " + ", ".join(feedback))
                else:
                    st.success("✅ All password requirements met!")
            
            submitted = st.form_submit_button("Register")
            
            if submitted:
                if not reg_email or not reg_password:
                    st.error("❌ Please fill all fields!")
                elif reg_password != reg_password_confirm:
                    st.error("❌ Passwords do not match!")
                elif len(reg_password) < 8:
                    st.error("❌ Password must be at least 8 characters!")
                elif "@" not in reg_email:
                    st.error("❌ Please enter a valid email!")
                else:
                    success, message = sign_up_user(reg_email, reg_password, reg_role)
                    if success:
                        st.success(f"✅ {message}")
                        st.info("📧 Please check your email to verify your account!")
                    else:
                        st.error(f"❌ {message}")
        
        if st.button("← Back to Login"):
            st.session_state.show_register = False
            st.rerun()
    
    # Login Page
    else:
        with st.form("login_form"):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            
            if submitted:
                if not email or not password:
                    st.error("❌ Please fill all fields!")
                elif "@" not in email:
                    st.error("❌ Please enter a valid email!")
                else:
                    success, message, role = sign_in_user(email, password)
                    if success:
                        st.session_state.logged_in = True
                        st.session_state.email = email
                        st.session_state.role = role
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
        
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

# ✅ DASHBOARD CODE
else:
    # Profile Page
    if st.session_state.show_profile:
        st.title("👤 My Profile")
        
        st.markdown(f"**Email:** {st.session_state.email}")
        st.markdown(f"**Role:** {st.session_state.role}")
        
        st.markdown("### Change Password")
        with st.form("change_password_form"):
            new_password = st.text_input("New Password", type="password")
            new_password_confirm = st.text_input("Confirm New Password", type="password")
            
            if new_password:
                strength, color, feedback = check_password_strength(new_password)
                st.markdown(f"**Password Strength:** {strength} {color}")
            
            submitted = st.form_submit_button("Update Password")
            
            if submitted:
                if new_password != new_password_confirm:
                    st.error("❌ Passwords do not match!")
                elif len(new_password) < 8:
                    st.error("❌ Password must be at least 8 characters!")
                else:
                    success, message = update_user_password(new_password)
                    if success:
                        st.success("✅ Password updated successfully!")
                        time.sleep(1)
                        st.session_state.show_profile = False
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
        
        if st.button("← Back to Dashboard"):
            st.session_state.show_profile = False
            st.rerun()
        
        st.stop()
    
    # Admin Panel
    elif st.session_state.show_admin and st.session_state.role == "Admin":
        st.title("👨‍💼 Admin Panel")
        
        users_df = load_users()
        
        if users_df.empty:
            st.info("📭 No users found!")
        else:
            st.markdown("### Manage Users")
            
            display_df = users_df[["id", "username", "role", "created_at"]].copy()
            st.dataframe(display_df, use_container_width=True)
            
            st.markdown("### Delete User")
            with st.form("delete_user_form"):
                user_to_delete = st.selectbox("Select User", users_df["username"].tolist())
                submitted = st.form_submit_button("Delete User")
                
                if submitted:
                    user_id = users_df[users_df["username"] == user_to_delete].iloc[0]["id"]
                    if user_to_delete == st.session_state.email:
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
    
    # Main Dashboard
    st.sidebar.title(f"👤 {st.session_state.email}")
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
        sign_out_user()
        st.session_state.logged_in = False
        st.session_state.email = ""
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