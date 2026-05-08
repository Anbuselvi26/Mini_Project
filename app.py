# =========================================================
# IMPORTS
# =========================================================
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import io

from datetime import datetime

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# =========================================================
# PAGE CONFIG
# =========================================================
st.set_page_config(
    page_title="SentinelX NIDS",
    layout="wide"
)

# =========================================================
# UI STYLING
# =========================================================
st.markdown("""
<style>

html, body, [class*="css"] {
    font-family: "Inter", sans-serif;
    background-color: #0b1220;
    color: #e5e7eb;
}

.main {
    background-color: #0b1220;
}

.block-container {
    padding-top: 1.5rem;
    padding-bottom: 1rem;
    padding-left: 2rem;
    padding-right: 2rem;
}

/* =====================================================
SIDEBAR
===================================================== */
section[data-testid="stSidebar"] {
    background-color: #111827;
    border-right: 1px solid #1f2937;
}

section[data-testid="stSidebar"] * {
    color: #e5e7eb !important;
}

/* =====================================================
UPLOAD BUTTON FIX
===================================================== */

[data-testid="stFileUploaderDropzone"] {
    background-color: #1f2937 !important;
    border: 2px dashed #3b82f6 !important;
}

[data-testid="stFileUploaderDropzone"] * {
    color: #e5e7eb !important;
}

/* =====================================================
HEADERS
===================================================== */
h1 {
    color: #f9fafb;
    font-size: 2.4rem;
    font-weight: 700;
}

h2, h3 {
    color: #f3f4f6;
    font-weight: 600;
}

/* =====================================================
METRIC CARDS
===================================================== */
div[data-testid="metric-container"] {

    background: linear-gradient(
        145deg,
        #111827,
        #0f172a
    ) !important;

    border: 1px solid rgba(59, 130, 246, 0.18) !important;

    border-radius: 18px !important;

    padding: 22px 18px !important;

    box-shadow:
        0 0 0 1px rgba(255,255,255,0.03),
        0 6px 18px rgba(0,0,0,0.28) !important;
}

/* =====================================================
TABLES
===================================================== */
[data-testid="stDataFrame"] {
    border: 1px solid #1f2937;
    border-radius: 12px;
    overflow: hidden;
}

/* =====================================================
BUTTONS
===================================================== */
.stDownloadButton button {
    background-color: #2563eb;
    color: white;
    border-radius: 8px;
    border: none;
    padding: 0.5rem 1rem;
}

</style>
""", unsafe_allow_html=True)

# =========================================================
# HEADER
# =========================================================
st.title("SentinelX NIDS")

st.caption(
    "Real-time packet anomaly monitoring and intrusion detection system"
)

# =========================================================
# STATUS BAR
# =========================================================
colA, colB = st.columns([5, 1])

with colA:

    st.caption(
        f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

with colB:

    st.success("Operational")

st.markdown("<br>", unsafe_allow_html=True)

# =========================================================
# SIDEBAR
# =========================================================
st.sidebar.header("Detection Settings")

# LOWERED THRESHOLD FOR REALISTIC WIRESHARK DEMOS
spike_threshold = st.sidebar.slider(
    "Traffic Spike Threshold (pps)",
    min_value=20,
    max_value=500,
    value=80,
    step=5
)

mode = st.sidebar.radio(
    "Select Input",
    [
        "Normal Traffic Demo",
        "Attack Traffic Demo",
        "Upload attack.csv"
    ]
)

# =========================================================
# NORMAL DATA
# =========================================================
@st.cache_data
def generate_normal_data():

    np.random.seed(42)

    rows = []

    base_time = 1700000000.0

    ips = [
        "192.168.1.5",
        "192.168.1.10",
        "192.168.1.20",
        "10.0.0.5"
    ]

    for i in range(2000):

        rows.append([
            round(base_time + np.random.uniform(0, 60), 3),
            np.random.choice(ips),
            np.random.choice([
                "192.168.1.1",
                "8.8.8.8",
                "142.250.1.1"
            ]),
            np.random.randint(49152, 65535),
            np.random.choice([80, 443, 53, 22]),
            np.random.randint(60, 700)
        ])

    return pd.DataFrame(
        rows,
        columns=[
            "time",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "length"
        ]
    )

# =========================================================
# ATTACK DATA
# =========================================================
@st.cache_data
def generate_attack_data():

    df = generate_normal_data()

    rows = []

    base_time = 1700000030

    # PORT SCAN
    for port in range(1, 500):

        rows.append([
            base_time + port * 0.01,
            "192.168.1.99",
            "192.168.1.1",
            55555,
            port,
            60
        ])

    # SYN FLOOD
    for i in range(1000):

        rows.append([
            base_time + np.random.uniform(0, 2),
            "10.10.10.10",
            "192.168.1.1",
            np.random.randint(1000,65535),
            80,
            60
        ])

    # DATA EXFIL
    for i in range(80):

        rows.append([
            base_time + 10 + i * 0.1,
            "192.168.1.5",
            "203.0.113.1",
            54000+i,
            4444,
            np.random.randint(1300, 1800)
        ])

    attack_df = pd.DataFrame(
        rows,
        columns=df.columns
    )

    return pd.concat(
        [df, attack_df],
        ignore_index=True
    )

# =========================================================
# LOAD DATA
# =========================================================
if mode == "Upload attack.csv":

    uploaded = st.sidebar.file_uploader(
        "Upload CSV",
        type=["csv", "txt"]
    )

    if uploaded:

        df_raw = pd.read_csv(
            uploaded,
            sep=None,
            engine="python",
            header=None
        )

        df_raw.columns = [
            "time",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "length"
        ]

    else:

        st.info("Upload attack.csv")
        st.stop()

elif mode == "Normal Traffic Demo":

    df_raw = generate_normal_data()

else:

    df_raw = generate_attack_data()

# =========================================================
# PROCESS DATA
# =========================================================
df = df_raw.copy()

numeric_cols = [
    "time",
    "src_port",
    "dst_port",
    "length"
]

for col in numeric_cols:

    df[col] = pd.to_numeric(
        df[col],
        errors="coerce"
    )

df = df.dropna()

df["time"] = pd.to_datetime(
    df["time"],
    unit="s"
)

df = df.sort_values("time")

# =========================================================
# FLOW FEATURES
# =========================================================
flow_df = (
    df.groupby("src_ip")
    .agg(
        packet_count=("length", "count"),
        avg_packet_size=("length", "mean"),
        max_packet_size=("length", "max"),
        unique_dst_ports=("dst_port", "nunique"),
        avg_dst_port=("dst_port", "mean"),
        std_packet_size=("length", "std")
    )
    .reset_index()
)

flow_df["std_packet_size"] = (
    flow_df["std_packet_size"]
    .fillna(0)
)

# =========================================================
# FEATURES
# =========================================================
features = flow_df[
    [
        "packet_count",
        "avg_packet_size",
        "max_packet_size",
        "unique_dst_ports",
        "avg_dst_port",
        "std_packet_size"
    ]
]

# =========================================================
# SCALING
# =========================================================
scaler = StandardScaler()

X_scaled = scaler.fit_transform(features)

# =========================================================
# ISOLATION FOREST
# =========================================================
model = IsolationForest(
    n_estimators=200,
    contamination=0.01,
    random_state=42
)

flow_df["prediction"] = model.fit_predict(X_scaled)

# =========================================================
# ANOMALIES
# =========================================================
anomalies = flow_df[
    flow_df["prediction"] == -1
]

# =========================================================
# SUSPICIOUS HOSTS
# =========================================================
suspects = anomalies.rename(
    columns={
        "src_ip": "IP Address",
        "packet_count": "Packets",
        "unique_dst_ports": "Unique Ports",
        "avg_packet_size": "Avg Packet Size"
    }
)[
    [
        "IP Address",
        "Packets",
        "Unique Ports",
        "Avg Packet Size"
    ]
]

# =========================================================
# TRAFFIC SPIKES
# =========================================================
pps = (
    df.set_index("time")
    .resample("1s")
    .size()
)

spikes = pps[
    pps >= spike_threshold
]

# =========================================================
# SYN FLOOD STYLE
# =========================================================
small_packets = df[
    df["length"] <= 70
]

syn_flood = (
    small_packets
    .groupby(["src_ip", "dst_port"])
    .size()
    .reset_index(name="packet_count")
)

syn_flood = syn_flood[
    syn_flood["packet_count"] >= 400
]

# =========================================================
# LARGE PAYLOADS
# =========================================================
large = df[
    df["length"] >= 1200
]

# =========================================================
# SUSPICIOUS PORTS
# =========================================================
suspicious_ports = [
    4444,
    5555,
    6666,
    1337,
    31337
]

malicious_port_activity = df[
    df["dst_port"].isin(suspicious_ports)
]

# =========================================================
# TOP TALKERS
# =========================================================
talkers = df["src_ip"].value_counts().head(10)

# =========================================================
# SMART GLOBAL SEVERITY
# =========================================================
critical = False
warning = False

# CRITICAL
if len(suspects) >= 2:
    critical = True

if len(syn_flood) >= 1:
    critical = True

if len(spikes) >= 5:
    critical = True

# WARNING
if len(suspects) == 1:
    warning = True

if len(large) >= 5:
    warning = True

if len(malicious_port_activity) >= 3:
    warning = True

# FINAL STATUS
if critical:

    st.error(
        "🔴 CRITICAL: Active malicious network behavior detected"
    )

elif warning:

    st.warning(
        "🟡 WARNING: Suspicious network activity observed"
    )

else:

    st.success(
        "🟢 CLEAN: No suspicious activity detected"
    )

# =========================================================
# METRICS
# =========================================================
st.subheader("Network Overview")

c1, c2, c3, c4 = st.columns(4)

c1.metric(
    "Packets Analyzed",
    f"{len(df):,}"
)

c2.metric(
    "Traffic Anomalies",
    len(spikes)
)

c3.metric(
    "Suspicious Hosts",
    len(suspects)
)

c4.metric(
    "Oversized Payloads",
    len(large)
)

# =========================================================
# CHARTS
# =========================================================
left, right = st.columns([2, 1])

with left:

    st.subheader("Traffic Activity Timeline")

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=pps.index,
        y=pps.values,
        mode="lines",
        line=dict(
            color="#3b82f6",
            width=2
        )
    ))

    fig.add_hline(
        y=spike_threshold,
        line_dash="dash",
        line_color="#f59e0b"
    )

    fig.update_layout(
        template="plotly_dark",
        height=400,
        paper_bgcolor="#111827",
        plot_bgcolor="#111827"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

with right:

    st.subheader("Top Source Hosts")

    talkers_df = pd.DataFrame({
        "IP": talkers.index,
        "Packets": talkers.values
    })

    fig2 = px.bar(
        talkers_df,
        x="Packets",
        y="IP",
        orientation="h",
        template="plotly_dark"
    )

    fig2.update_layout(
        paper_bgcolor="#111827",
        plot_bgcolor="#111827"
    )

    st.plotly_chart(
        fig2,
        use_container_width=True
    )

# =========================================================
# ANALYSIS
# =========================================================
left2, right2 = st.columns(2)

with left2:

    st.subheader("ML-Based Threat Analysis")

    if len(suspects) > 0:

        st.warning(
            "Anomalous hosts detected by Isolation Forest"
        )

        st.dataframe(
            suspects,
            use_container_width=True,
            hide_index=True
        )

    if len(syn_flood) > 0:

        st.error(
            "Potential SYN Flood detected"
        )

        st.dataframe(
            syn_flood,
            use_container_width=True,
            hide_index=True
        )

    if len(malicious_port_activity) > 0:

        st.warning(
            "Suspicious ports detected"
        )

        show_ports = malicious_port_activity.copy()

        show_ports["time"] = (
            show_ports["time"]
            .dt.strftime("%H:%M:%S.%f")
            .str[:-3]
        )

        st.dataframe(
            show_ports[
                [
                    "time",
                    "src_ip",
                    "dst_ip",
                    "src_port",
                    "dst_port",
                    "length"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )

    if (
        len(suspects) == 0
        and len(syn_flood) == 0
        and len(malicious_port_activity) == 0
    ):

        st.success(
            "No suspicious activity detected"
        )

with right2:

    st.subheader("Packet Size Distribution")

    fig4 = px.histogram(
        df,
        x="length",
        nbins=40,
        template="plotly_dark"
    )

    fig4.add_vline(
        x=1200,
        line_dash="dash",
        line_color="#ef4444"
    )

    fig4.update_layout(
        paper_bgcolor="#111827",
        plot_bgcolor="#111827",
        height=300
    )

    st.plotly_chart(
        fig4,
        use_container_width=True
    )

# =========================================================
# SUSPICIOUS PAYLOAD EVENTS
# =========================================================
st.subheader("Suspicious Payload Events")

if len(large) > 0:

    st.warning(
        "Oversized payload traffic identified"
    )

    row_limit = st.selectbox(
        "Rows to display",
        [10, 20, 50, 100],
        index=1
    )

    show = large.copy()

    show["time"] = (
        show["time"]
        .dt.strftime("%H:%M:%S.%f")
        .str[:-3]
    )

    st.dataframe(
        show[
            [
                "time",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "length"
            ]
        ].head(row_limit),
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No oversized payload events detected"
    )

# =========================================================
# RAW DATA
# =========================================================
with st.expander("Packet Telemetry"):

    st.dataframe(
        df.head(100),
        use_container_width=True
    )

# =========================================================
# DOWNLOAD
# =========================================================
csv_buf = io.StringIO()

df.to_csv(
    csv_buf,
    index=False
)

st.download_button(
    "Download Processed Dataset",
    data=csv_buf.getvalue(),
    file_name="nids_processed.csv",
    mime="text/csv"
)

# =========================================================
# FOOTER
# =========================================================
st.caption(
    "SentinelX NIDS • ML-Powered Network Intrusion Detection System"
)