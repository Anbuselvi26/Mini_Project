import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
from collections import Counter
import io
import os

st.set_page_config(page_title="Network IDS Dashboard", layout="wide")

# ===============================
# Styling
# ===============================
st.markdown("""
<style>
    .main { background-color: #0a1628; }
    .stMetric { background-color: #112240; border-radius: 10px; padding: 10px; }
    h1 { color: #00bcd4; }
    h2, h3 { color: #e8f4fd; }
</style>
""", unsafe_allow_html=True)

st.title("🚨 Network Intrusion Detection Dashboard")
st.caption("Wireshark-based Packet-Level Anomaly Detection | Real-time NIDS Demo")

# ===============================
# Sidebar — Upload or use sample
# ===============================
st.sidebar.header("📂 Data Source")
mode = st.sidebar.radio("Choose input", ["Use sample data (demo)", "Upload attack.csv"])

def generate_sample_data():
    """Generate realistic demo data: baseline + port scan burst + large packet burst"""
    np.random.seed(42)
    rows = []
    base_time = 1700000000.0
    ips = ["192.168.1.5", "192.168.1.10", "192.168.1.20", "10.0.0.5"]

    # Normal traffic (0–30s)
    for i in range(800):
        t = base_time + np.random.uniform(0, 30)
        src = np.random.choice(ips)
        dst = np.random.choice(["192.168.1.1", "8.8.8.8", "142.250.1.1"])
        sport = np.random.randint(49152, 65535)
        dport = np.random.choice([80, 443, 53, 22, 8080])
        length = np.random.randint(60, 800)
        rows.append([round(t, 3), src, dst, sport, dport, length])

    # Port scan burst (30–35s) — attacker hits 500 ports
    attacker = "192.168.1.99"
    for port in range(1, 501):
        t = base_time + 30 + port * 0.01
        rows.append([round(t, 3), attacker, "192.168.1.1", 54321, port, 60])

    # Traffic spike (35–40s) — DDoS simulation
    for i in range(1500):
        t = base_time + 35 + np.random.uniform(0, 5)
        src = f"10.0.{np.random.randint(0,255)}.{np.random.randint(1,254)}"
        rows.append([round(t, 3), src, "192.168.1.1", np.random.randint(1024,65535), 80, np.random.randint(60,200)])

    # Large packets (40–50s) — data exfiltration simulation
    for i in range(80):
        t = base_time + 40 + i * 0.1
        rows.append([round(t, 3), "192.168.1.5", "203.0.113.1", 54000+i, 443, np.random.randint(1300, 1500)])

    # More normal traffic (50–60s)
    for i in range(400):
        t = base_time + 50 + np.random.uniform(0, 10)
        src = np.random.choice(ips)
        dst = np.random.choice(["192.168.1.1", "8.8.8.8"])
        rows.append([round(t, 3), src, dst, np.random.randint(49152,65535), np.random.choice([80,443,53]), np.random.randint(60,600)])

    df = pd.DataFrame(rows, columns=["time","src_ip","dst_ip","src_port","dst_port","length"])
    return df.sort_values("time").reset_index(drop=True)

# ===============================
# Load Data
# ===============================
df_raw = None

if mode == "Upload attack.csv":
    uploaded = st.sidebar.file_uploader("Upload attack.csv", type=["csv","txt"])
    if uploaded:
        try:
            df_raw = pd.read_csv(uploaded, sep="\t", header=None)
        except Exception as e:
            st.error(f"Failed to read file: {e}")
            st.stop()
    else:
        st.info("👈 Upload your attack.csv file from tshark export, or switch to sample data.")
        st.stop()
else:
    df_raw = generate_sample_data()
    st.sidebar.success("✅ Using generated demo data (3,280 packets)")

# ===============================
# Data Processing
# ===============================
df = df_raw.copy()
if df.shape[1] != 6:
    st.error(f"Expected 6 columns, got {df.shape[1]}. Check your CSV format.")
    st.stop()

df.columns = ["time", "src_ip", "dst_ip", "src_port", "dst_port", "length"]

df["time"]     = pd.to_numeric(df["time"],     errors="coerce")
df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
df["length"]   = pd.to_numeric(df["length"],   errors="coerce")
df = df.dropna()
df["time"] = pd.to_datetime(df["time"], unit="s")
df = df.set_index("time").sort_index()

# ===============================
# Detections
# ===============================
port_scan   = df.groupby("src_ip")["dst_port"].nunique()
suspects    = port_scan[port_scan > 50].reset_index()
suspects.columns = ["IP Address", "Unique Ports Scanned"]

pps         = df.resample("1s").size()
spikes      = pps[pps > 100]

large       = df[df["length"] > 1200]
talkers     = df["src_ip"].value_counts().head(10)

# ===============================
# Sidebar — Thresholds
# ===============================
st.sidebar.markdown("---")
st.sidebar.header("⚙️ Detection Thresholds")
port_thresh  = st.sidebar.slider("Port scan threshold (unique ports)", 10, 200, 50)
spike_thresh = st.sidebar.slider("Traffic spike threshold (pps)", 20, 500, 100)
pkt_thresh   = st.sidebar.slider("Large packet threshold (bytes)", 500, 1500, 1200)

suspects = port_scan[port_scan > port_thresh].reset_index()
suspects.columns = ["IP Address", "Unique Ports Scanned"]
pps      = df.resample("1s").size()
spikes   = pps[pps > spike_thresh]
large    = df[df["length"] > pkt_thresh]

# ===============================
# Metrics Row
# ===============================
st.markdown("### 📊 Overview")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Packets",        f"{len(df):,}")
c2.metric("Traffic Spikes",       len(spikes),   delta=f">{spike_thresh} pps", delta_color="inverse")
c3.metric("Port Scan Suspects",   len(suspects), delta=f">{port_thresh} ports", delta_color="inverse")
c4.metric("Large Packets",        len(large),    delta=f">{pkt_thresh} bytes", delta_color="inverse")

st.markdown("---")

# ===============================
# Row 1: Traffic + Top Talkers
# ===============================
left, right = st.columns([2, 1])

with left:
    st.subheader("📈 Packets per Second (with anomaly markers)")
    fig, ax = plt.subplots(figsize=(10, 4))
    fig.patch.set_facecolor("#0a1628")
    ax.set_facecolor("#112240")
    ax.plot(pps.index, pps.values, color="#00bcd4", linewidth=1.8, label="PPS")
    if not spikes.empty:
        ax.scatter(spikes.index, spikes.values, color="#ff5252", s=60, zorder=5, label=f"Spike (>{spike_thresh})")
    ax.axhline(spike_thresh, color="#ffd740", linewidth=1, linestyle="--", alpha=0.7, label="Threshold")
    ax.set_xlabel("Time", color="#90a4ae")
    ax.set_ylabel("Packets/sec", color="#90a4ae")
    ax.tick_params(colors="#90a4ae")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    plt.xticks(rotation=30)
    ax.legend(facecolor="#112240", labelcolor="#e8f4fd", fontsize=9)
    ax.grid(True, color="#1e3a5f", linewidth=0.5)
    for spine in ax.spines.values():
        spine.set_edgecolor("#1e3a5f")
    st.pyplot(fig)
    plt.close()

with right:
    st.subheader("🗣️ Top Talkers (src IP)")
    fig2, ax2 = plt.subplots(figsize=(5, 4))
    fig2.patch.set_facecolor("#0a1628")
    ax2.set_facecolor("#112240")
    colors = ["#ff5252" if ip == (suspects["IP Address"].iloc[0] if not suspects.empty else "") else "#00bcd4"
              for ip in talkers.index]
    ax2.barh(talkers.index[::-1], talkers.values[::-1], color=colors[::-1])
    ax2.set_xlabel("Packet Count", color="#90a4ae")
    ax2.tick_params(colors="#90a4ae", labelsize=9)
    ax2.grid(True, axis="x", color="#1e3a5f", linewidth=0.5)
    for spine in ax2.spines.values():
        spine.set_edgecolor("#1e3a5f")
    st.pyplot(fig2)
    plt.close()

st.markdown("---")

# ===============================
# Row 2: Port Scan + Packet Length
# ===============================
left2, right2 = st.columns(2)

with left2:
    st.subheader("🚨 Port Scan Detection")
    if not suspects.empty:
        st.error(f"⚠️ {len(suspects)} suspicious IP(s) detected scanning >{port_thresh} ports")
        st.dataframe(suspects, use_container_width=True, hide_index=True)
        # Bar chart of scanned ports per suspect
        fig3, ax3 = plt.subplots(figsize=(6, 3))
        fig3.patch.set_facecolor("#0a1628")
        ax3.set_facecolor("#112240")
        ax3.bar(suspects["IP Address"], suspects["Unique Ports Scanned"], color="#ff5252")
        ax3.set_ylabel("Unique Ports", color="#90a4ae")
        ax3.tick_params(colors="#90a4ae", labelsize=8)
        ax3.axhline(port_thresh, color="#ffd740", linewidth=1, linestyle="--", alpha=0.8)
        for spine in ax3.spines.values():
            spine.set_edgecolor("#1e3a5f")
        st.pyplot(fig3)
        plt.close()
    else:
        st.success("✅ No port scan activity detected")

with right2:
    st.subheader("📦 Packet Length Distribution")
    fig4, ax4 = plt.subplots(figsize=(6, 3))
    fig4.patch.set_facecolor("#0a1628")
    ax4.set_facecolor("#112240")
    ax4.hist(df["length"], bins=40, color="#00897b", edgecolor="#0a1628", linewidth=0.3)
    ax4.axvline(pkt_thresh, color="#ff5252", linewidth=1.5, linestyle="--", label=f"Threshold ({pkt_thresh}B)")
    ax4.set_xlabel("Packet Length (bytes)", color="#90a4ae")
    ax4.set_ylabel("Count", color="#90a4ae")
    ax4.tick_params(colors="#90a4ae")
    ax4.legend(facecolor="#112240", labelcolor="#e8f4fd", fontsize=9)
    ax4.grid(True, color="#1e3a5f", linewidth=0.5)
    for spine in ax4.spines.values():
        spine.set_edgecolor("#1e3a5f")
    st.pyplot(fig4)
    plt.close()

st.markdown("---")

# ===============================
# Large Packets Table
# ===============================
st.subheader("📦 Large Packet Records (potential exfiltration)")
if not large.empty:
    st.warning(f"{len(large)} packets exceed {pkt_thresh} bytes")
    show = large[["src_ip","dst_ip","src_port","dst_port","length"]].reset_index()
    show["time"] = show["time"].dt.strftime("%H:%M:%S.%f").str[:-3]
    st.dataframe(show.head(20), use_container_width=True, hide_index=True)
else:
    st.success("No oversized packets found")

st.markdown("---")

# ===============================
# Raw Data + Download
# ===============================
with st.expander("🔍 Raw packet data"):
    st.dataframe(df.reset_index().head(100), use_container_width=True)

csv_buf = io.StringIO()
df.reset_index().to_csv(csv_buf, index=False)
st.download_button(
    "⬇️ Download processed data as CSV",
    data=csv_buf.getvalue(),
    file_name="nids_processed.csv",
    mime="text/csv"
)

st.caption("Demo: Wireshark Packet-Level Traffic Analysis for Anomaly Detection | Cybersecurity Tools Seminar")
