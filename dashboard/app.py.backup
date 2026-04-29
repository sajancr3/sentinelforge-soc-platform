import streamlit as st
import pandas as pd
import json
import os
import time

st.set_page_config(page_title="SentinelForge SOC", layout="wide")

LOG_FILE = "logs/enriched_alerts.json"


def load_data():
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame()

    try:
        with open(LOG_FILE, "r") as f:
            data = json.load(f)

        if not isinstance(data, list):
            return pd.DataFrame()

        return pd.DataFrame(data)

    except Exception:
        return pd.DataFrame()


st.title("🛡️ SentinelForge Elite SOC Dashboard")
st.caption("Detection • Correlation • Risk Scoring • GeoIP • Automated Response")

df = load_data()

if df.empty:
    st.warning("No alerts yet. Run an approved lab scan from the attacker VM.")
else:
    for col in ["severity", "risk_level", "attack_type", "source_ip", "country", "city", "isp", "response", "response_action"]:
        if col not in df.columns:
            df[col] = "N/A"

    if "risk_score" not in df.columns:
        df["risk_score"] = 0

    if "events" not in df.columns:
        df["events"] = df.get("events_from_ip", 0)

    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Alerts", len(df))
    c2.metric("Unique Attackers", df["source_ip"].nunique())
    c3.metric("Max Risk", int(df["risk_score"].max()))
    c4.metric("Critical Alerts", int((df["risk_level"] == "Critical").sum()))
    c5.metric("Avg Risk", int(df["risk_score"].mean()))

    st.divider()

    st.subheader("🎯 Filters")

    risk_options = sorted(df["risk_level"].dropna().unique())
    attack_options = sorted(df["attack_type"].dropna().unique())

    selected_risks = st.multiselect(
        "Risk Level",
        risk_options,
        default=risk_options,
        key="risk_filter"
    )

    selected_attacks = st.multiselect(
        "Attack Type",
        attack_options,
        default=attack_options,
        key="attack_filter"
    )

    filtered = df[
        df["risk_level"].isin(selected_risks) &
        df["attack_type"].isin(selected_attacks)
    ]

    st.divider()

    st.subheader("🚨 Recent Alerts")

    visible_cols = [
        "timestamp",
        "alert",
        "attack_type",
        "source_ip",
        "destination_ip",
        "country",
        "city",
        "isp",
        "risk_score",
        "risk_level",
        "classification",
        "response",
    ]

    visible_cols = [c for c in visible_cols if c in filtered.columns]

    st.dataframe(
        filtered[visible_cols].sort_values("timestamp", ascending=False),
        use_container_width=True
    )

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Top Attacker IPs")
        st.bar_chart(filtered["source_ip"].value_counts())

    with right:
        st.subheader("Attack Types")
        st.bar_chart(filtered["attack_type"].value_counts())

    st.divider()

    left2, right2 = st.columns(2)

    with left2:
        st.subheader("Risk Score Trend")
        st.line_chart(filtered["risk_score"])

    with right2:
        st.subheader("GeoIP / Location")
        st.dataframe(
            filtered[["source_ip", "country", "city", "isp"]].drop_duplicates(),
            use_container_width=True
        )

    st.divider()

    st.subheader("Response Actions")

    response_col = "response" if "response" in filtered.columns else "response_action"

    st.dataframe(
        filtered[["source_ip", "risk_score", "risk_level", response_col]],
        use_container_width=True
    )

time.sleep(3)
st.rerun()
