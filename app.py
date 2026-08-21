import streamlit as st
import pandas as pd
data = pd.read_csv("data/threats.csv")

st.set_page_config(
    page_title="DarkWatch",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ DarkWatch")
st.subheader("Dark Web Threat Intelligence Dashboard")

st.write(
    "Monitor, analyze and visualize simulated cyber threat intelligence data."
)

st.divider()

col1, col2, col3 = st.columns(3)

total_threats = len(data)
high_risk = len(data[data["severity"].isin(["High", "Critical"])])
active_alerts = len(data[data["status"] == "Active"])

with col1:
    st.metric("Total Threats", total_threats)

with col2:
    st.metric("High Risk Threats", high_risk)

with col3:
    st.metric("Active Alerts", active_alerts)

st.divider()

st.info("Threat intelligence data will appear here.")
st.subheader("Threat Records")



st.dataframe(data)