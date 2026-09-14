import streamlit as st
import bcrypt
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from supabase import create_client, Client
from datetime import datetime, timedelta
import random

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
if "email" not in st.session_state:
    st.session_state.email = ""
if "otp_verified" not in st.session_state:
    st.session_state.otp_verified = False
if "otp_email" not in st.session_state:
    st.session_state.otp_email = ""

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

def generate_otp() -> str:
    return "".join([str(random.randint(0, 9)) for _ in range(6)])

def send_otp_email(to_email: str, otp: str):
    smtp_host = st.secrets["smtp"]["host"]
    smtp_port = st.secrets["smtp"]["port"]
    smtp_user = st.secrets["smtp"]["user"]
    smtp_password = st.secrets["smtp"]["password"]

    msg = MIMEMultipart()
    msg["From"] = smtp_user
    msg["To"] = to_email
    msg["Subject"] = "DarkWatch - Your OTP Code"

    body = f"""Hello,

Your DarkWatch OTP code is: {otp}

This code is valid for 10 minutes. Do not share it with anyone.

If you did not request this, please ignore this email.

Thanks,
DarkWatch Security Team
"""
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)

def save_otp_to_db(email: str, otp: str, purpose: str):
    expires_at = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    supabase.table("otp_verifications").insert({
        "email": email,
        "otp": otp,
        "purpose": purpose,
        "expires_at": expires_at,
        "verified": False
    }).execute()

def verify_otp_in_db(email: str, otp: str) -> bool:
    now = datetime.utcnow().isoformat()
    response = (
        supabase.table("otp_verifications")
        .select("*")
        .eq("email", email)
        .eq("otp", otp)
        .eq("verified", False)
        .gte("expires_at", now)
        .execute()
    )
    if response.data:
        supabase.table("otp_verifications").update({"verified": True}).eq("email", email).eq("otp", otp).execute()
        return True
    return False

def get_user_by_username(username: str):
    response = supabase.table("users").select("*").eq("username", username).execute()
    return response.data[0] if response.data else None

def get_user_by_email(email: str):
    response = supabase.table("users").select("*").eq("email", email).eq("role", "user").execute()
    return response.data[0] if response.data else None

def update_user_password(user_id: str, new_hashed_pw: str):
    supabase.table("users").update({"password": new_hashed_pw}).eq("id", user_id).execute()

def update_user_email(user_id: str, new_email: str):
    supabase.table("users").update({"email": new_email}).eq("id", user_id).execute()

def save_event(event_type: str, severity: str, source_ip: str, target: str, status: str):
    supabase.table("security_events").insert({
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "target": target,
        "status": status
    }).execute()

def analyze_threat_text(threat_text):
    text = threat_text.lower().strip()

    critical_indicators = {
        "ransomware": 6,
        "zero-day": 6,
        "zero day": 6,
        "data breach": 5,
        "major breach": 5,
        "critical breach": 5,
        "privilege escalation": 5,
        "administrator-level privileges": 5,
        "administrator privileges": 5,
        "admin privileges": 5,
        "domain admin": 6,
        "root access": 6,
        "remote code execution": 6,
        "unauthorized access": 4,
        "full system compromise": 6,
        "account takeover": 5,
        "exfiltration": 5,
        "stolen database": 5,
        "database dump": 5
    }

    high_indicators = {
        "exploit": 3,
        "vulnerability": 3,
        "leaked credentials": 4,
        "stolen credentials": 4,
        "credential theft": 4,
        "password leak": 4,
        "data leak": 3,
        "malware": 3,
        "phishing": 3,
        "malicious": 3,
        "suspicious login": 3,
        "account manipulation": 3,
        "elevated privileges": 4,
        "unapproved change": 3,
        "lateral movement": 4,
        "command and control": 4,
        "backdoor": 4,
        "trojan": 3,
        "spyware": 3,
        "brute force": 3,
        "ddos": 3
    }

    medium_indicators = {
        "suspicious": 1,
        "unusual": 1,
        "failed login": 2,
        "multiple login attempts": 2,
        "unknown ip": 2,
        "unrecognized device": 2,
        "security alert": 1,
        "abnormal activity": 2,
        "policy violation": 2,
        "permission change": 2
    }

    score = 0
    detected_indicators = []

    for phrase, points in critical_indicators.items():
        if phrase in text:
            score += points
            detected_indicators.append(f"{phrase} (+{points})")

    for phrase, points in high_indicators.items():
        if phrase in text:
            score += points
            detected_indicators.append(f"{phrase} (+{points})")

    for phrase, points in medium_indicators.items():
        if phrase in text:
            score += points
            detected_indicators.append(f"{phrase} (+{points})")

    impact_words = [
        "financial data",
        "customer data",
        "personal data",
        "confidential data",
        "sensitive data",
        "production server",
        "critical system",
        "payment system",
        "government system"
    ]

    for phrase in impact_words:
        if phrase in text:
            score += 2
            detected_indicators.append(f"{phrase} (+2)")

    score = min(score, 20)

    if score >= 12:
        severity = "Critical"
        color = "🔴"
    elif score >= 7:
        severity = "High"
        color = "🟠"
    elif score >= 3:
        severity = "Medium"
        color = "🟡"
    else:
        severity = "Low"
        color = "🟢"

    serious_phrases = [
        "privilege escalation",
        "administrator-level privileges",
        "admin privileges",
        "ransomware",
        "zero-day",
        "remote code execution",
        "domain admin",
        "root access",
        "data breach"
    ]

    if any(phrase in text for phrase in serious_phrases) and severity in ["Low", "Medium"]:
        severity = "High"
        color = "🟠"

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
            ["Login", "Register", "Forgot Password"],
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
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            submit = st.form_submit_button("Register")

        if submit:
            if not username or not email or not password:
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
                    existing_email = get_user_by_email(email)
                    if existing_email:
                        st.error("❌ Email already registered.")
                    else:
                        hashed_pw = hash_password(password)
                        try:
                            supabase.table("users").insert({
                                "username": username,
                                "email": email,
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
                st.session_state.email = user.get("email", "")
                st.success("✅ Login successful!")
                st.rerun()

    elif page == "Forgot Password":
        st.title("🔑 Forgot Password - DarkWatch")

        if "forgot_step" not in st.session_state:
            st.session_state.forgot_step = 1
        if "fp_username" not in st.session_state:
            st.session_state.fp_username = ""
        if "fp_user_id" not in st.session_state:
            st.session_state.fp_user_id = ""
        if "fp_email" not in st.session_state:
            st.session_state.fp_email = ""

        if st.session_state.forgot_step == 1:
            with st.form("fp_step1", clear_on_submit=False):
                username = st.text_input("Enter your username")
                submit = st.form_submit_button("Send OTP")

            if submit:
                user = get_user_by_username(username)
                if not user or not user.get("email"):
                    st.error("❌ Username not found or no email registered.")
                else:
                    st.session_state.forgot_step = 2
                    st.session_state.fp_username = username
                    st.session_state.fp_user_id = user["id"]
                    st.session_state.fp_email = user["email"]
                    otp = generate_otp()
                    send_otp_email(user["email"], otp)
                    save_otp_to_db(user["email"], otp, "forgot_password")
                    st.success(f"✅ OTP sent to {user['email']}")
                    st.rerun()

        elif st.session_state.forgot_step == 2:
            with st.form("fp_step2", clear_on_submit=False):
                otp = st.text_input("Enter OTP")
                submit = st.form_submit_button("Verify OTP")

            if submit:
                if verify_otp_in_db(st.session_state.fp_email, otp):
                    st.session_state.forgot_step = 3
                    st.success("✅ OTP verified! Set new password.")
                    st.rerun()
                else:
                    st.error("❌ Invalid or expired OTP.")

        elif st.session_state.forgot_step == 3:
            with st.form("fp_step3", clear_on_submit=False):
                new_password = st.text_input("New Password", type="password")
                confirm_password = st.text_input("Confirm New Password", type="password")
                submit = st.form_submit_button("Reset Password")

            if submit:
                if new_password != confirm_password:
                    st.error("❌ Passwords do not match.")
                elif len(new_password) < 6:
                    st.error("❌ Password must be at least 6 characters.")
                else:
                    new_hashed = hash_password(new_password)
                    update_user_password(st.session_state.fp_user_id, new_hashed)
                    for key in ["forgot_step", "fp_username", "fp_user_id", "fp_email"]:
                        if key in st.session_state:
                            del st.session_state[key]
                    st.success("✅ Password reset successful! Please login.")
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
            if "created_at" in df.columns:
                display_df = df.sort_values("created_at", ascending=False).head(10)[
                    ["event_type", "severity", "source_ip", "target", "status", "created_at"]
                ]
            else:
                display_df = df.head(10)[
                    ["event_type", "severity", "source_ip", "target", "status"]
                ]
            
            st.dataframe(
                display_df,
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
            placeholder="Example: A normal user account unexpectedly obtained administrator-level privileges without an approved change request."
        )

        if st.button("Analyze"):
            if not threat_text.strip():
                st.warning("⚠️ Please paste some text to analyze.")
            else:
                score, severity, color, detected_indicators = analyze_threat_text(threat_text)

                st.markdown(f"### Threat Score: {score}/20 {color}")
                st.markdown(f"### Severity: {severity}")

                if detected_indicators:
                    st.markdown("#### Detected Risk Indicators")
                    for indicator in detected_indicators:
                        st.write(f"• {indicator}")
                else:
                    st.info("ℹ️ No known high-risk indicators were detected in this text.")

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

        try:
            events = supabase.table("security_events").select("*").order("created_at", desc=True).execute().data or []
        except:
            events = supabase.table("security_events").select("*").execute().data or []
        
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

            if "created_at" in df.columns:
                display_cols = ["event_type", "severity", "source_ip", "target", "status", "created_at"]
            else:
                display_cols = ["event_type", "severity", "source_ip", "target", "status"]

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

            st.subheader("Event Timeline")
            if "created_at" in df.columns:
                df["created_at"] = pd.to_datetime(df["created_at"])
                df["date"] = df["created_at"].dt.date
                timeline = df.groupby(["date", "severity"]).size().unstack(fill_value=0)
                st.line_chart(timeline)
            else:
                st.info("ℹ️ No timestamp data available for timeline.")

    elif page == "Profile":
        st.title("👤 Profile - DarkWatch")

        user = get_user_by_username(st.session_state.username)

        st.write(f"**Username:** {user['username']}")
        st.write(f"**Email:** {user.get('email', 'Not set')}")
        st.write(f"**Role:** {user['role']}")

        with st.form("update_profile", clear_on_submit=False):
            new_email = st.text_input("New Email", value=user.get("email", ""))
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")
            submit = st.form_submit_button("Update Profile")

        if submit:
            if new_email and new_email != user.get("email", ""):
                existing = get_user_by_email(new_email)
                if existing and existing["id"] != user["id"]:
                    st.error("❌ Email already in use.")
                else:
                    update_user_email(user["id"], new_email)
                    st.session_state.email = new_email
                    st.success("✅ Email updated!")

            if new_password:
                if new_password != confirm_password:
                    st.error("❌ Passwords do not match.")
                elif len(new_password) < 6:
                    st.error("❌ Password must be at least 6 characters.")
                else:
                    new_hashed = hash_password(new_password)
                    update_user_password(user["id"], new_hashed)
                    st.success("✅ Password updated!")

            st.rerun()

    elif page == "Admin Panel":
        if st.session_state.role !="admin":
            st.error("❌ Access denied. Admins only.")
        else:
            st.title("⚙️ Admin Panel - DarkWatch")

            tab1, tab2, tab3 = st.tabs(["Manage Threats", "Manage Users", "Audit Logs"])

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

            with tab3:
                st.subheader("Audit Logs")
                st.info("ℹ️ Audit logs feature coming soon.")