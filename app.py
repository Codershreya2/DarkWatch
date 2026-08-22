from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


st.set_page_config(
    page_title="DarkWatch",
    page_icon="🛡️",
    layout="wide"
)

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
    "threat_id",
    "threat_type",
    "severity",
    "source",
    "country",
    "date",
    "status",
}

missing_columns = required_columns - set(data.columns)

if missing_columns:
    st.error(
        f"Missing required columns: {', '.join(sorted(missing_columns))}"
    )
    st.stop()


data["date"] = pd.to_datetime(data["date"], errors="coerce")


st.title("🛡️ DarkWatch")
st.subheader("Dark Web Threat Intelligence Dashboard")
st.write(
    "Monitor, analyze and visualize simulated cyber threat intelligence data."
)


# ---------------- SIDEBAR FILTERS ----------------

st.sidebar.header("Filter Threat Records")

severity_options = sorted(data["severity"].dropna().unique())
country_options = sorted(data["country"].dropna().unique())
status_options = sorted(data["status"].dropna().unique())


selected_severity = st.sidebar.multiselect(
    "Severity",
    options=severity_options,
    default=severity_options
)

selected_countries = st.sidebar.multiselect(
    "Country",
    options=country_options,
    default=country_options
)

selected_status = st.sidebar.multiselect(
    "Status",
    options=status_options,
    default=status_options
)


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

high_risk = len(
    filtered_data[
        filtered_data["severity"].isin(["High", "Critical"])
    ]
)

active_alerts = len(
    filtered_data[
        filtered_data["status"].str.lower() == "active"
    ]
)


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
severity_counts = (
    filtered_data["severity"]
    .value_counts()
    .reindex(
        ["Low", "Medium", "High", "Critical"]
    )
    .dropna()
    .reset_index()
)

severity_counts.columns = ["severity", "count"]


severity_chart = px.bar(
    severity_counts,
    x="severity",
    y="count",
    color="severity",
    title="Threats by Severity",
    text="count"
)


with chart_col1:
    st.plotly_chart(
        severity_chart,
        use_container_width=True
    )


# Threat Type Chart
threat_type_counts = (
    filtered_data["threat_type"]
    .value_counts()
    .reset_index()
)

threat_type_counts.columns = [
    "threat_type",
    "count"
]


threat_type_chart = px.bar(
    threat_type_counts,
    x="threat_type",
    y="count",
    color="threat_type",
    title="Threats by Type",
    text="count"
)


with chart_col2:
    st.plotly_chart(
        threat_type_chart,
        use_container_width=True
    )


chart_col3, chart_col4 = st.columns(2)


# Country Chart
country_counts = (
    filtered_data["country"]
    .value_counts()
    .reset_index()
)

country_counts.columns = [
    "country",
    "count"
]


country_chart = px.bar(
    country_counts,
    x="country",
    y="count",
    color="country",
    title="Threats by Country",
    text="count"
)


with chart_col3:
    st.plotly_chart(
        country_chart,
        use_container_width=True
    )


# Source Chart
source_counts = (
    filtered_data["source"]
    .value_counts()
    .reset_index()
)

source_counts.columns = [
    "source",
    "count"
]


source_chart = px.bar(
    source_counts,
    x="source",
    y="count",
    color="source",
    title="Threats by Source",
    text="count"
)


with chart_col4:
    st.plotly_chart(
        source_chart,
        use_container_width=True
    )


# Trend Chart
daily_threats = (
    filtered_data
    .dropna(subset=["date"])
    .groupby("date")
    .size()
    .reset_index(name="count")
    .sort_values("date")
)


if not daily_threats.empty:

    trend_chart = px.line(
        daily_threats,
        x="date",
        y="count",
        markers=True,
        title="Daily Threat Trend"
    )

    st.plotly_chart(
        trend_chart,
        use_container_width=True
    )


# ---------------- TABLE ----------------

st.subheader("Filtered Threat Records")


display_data = filtered_data.copy()

display_data["date"] = (
    display_data["date"]
    .dt.strftime("%Y-%m-%d")
)


st.dataframe(
    display_data,
    use_container_width=True,
    hide_index=True
)