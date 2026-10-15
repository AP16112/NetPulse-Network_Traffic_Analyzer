import pandas as pd
import plotly.express as px
import streamlit as st
from netpulse.analysis import detect_spikes, traffic_series
from netpulse.capture import CAPACITY, CaptureSession, interfaces

st.set_page_config(page_title="NetPulse | Network intelligence", page_icon="📡", layout="wide")
st.markdown("""<style>
.block-container {padding-top:2rem; max-width:1600px}
h1 {letter-spacing:-1.5px} [data-testid="stMetric"] {background:#141e2c;border:1px solid #243247;border-radius:12px;padding:18px}
[data-testid="stSidebar"] {border-right:1px solid #243247}
</style>""", unsafe_allow_html=True)

if "capture" not in st.session_state:
    st.session_state.capture = CaptureSession()
    st.session_state.capture.seed_demo()
capture = st.session_state.capture

with st.sidebar:
    st.markdown("## ◉ NetPulse")
    st.caption("NETWORK TRAFFIC ANALYZER")
    st.divider()
    mode = st.selectbox("Data source", ["Demo", "Live capture", "PCAP file"])
    if mode != capture.mode:
        capture.clear()
        capture.mode = mode
        if mode == "Demo":
            capture.seed_demo()
    interface, bpf = None, ""
    if mode == "Live capture":
        choices = interfaces()
        interface = st.selectbox("Network interface", list(choices), format_func=choices.get) if choices else None
        bpf = st.text_input("Capture filter (BPF)", placeholder="tcp or udp or icmp")
        st.caption("Capture only networks you are authorized to monitor. Windows requires Npcap; driver settings may require administrator access.")
    if mode == "PCAP file":
        upload = st.file_uploader("Open capture", type=["pcap", "pcapng"])
        if st.button("Analyze file", disabled=upload is None, use_container_width=True):
            with st.spinner("Reading packet headers…"):
                count = capture.load_pcap(upload.getvalue())
            st.success(f"Read {count:,} packets")
        st.caption(f"Up to 25 MB and the first {CAPACITY:,} packets per file.")
    else:
        a, b = st.columns(2)
        if a.button("▶ Start", use_container_width=True, disabled=mode == "Live capture" and not interface):
            capture.start(mode, interface, bpf)
        if b.button("■ Stop", use_container_width=True):
            capture.stop()
    if st.button("Clear session", use_container_width=True):
        capture.clear()
    st.divider()
    st.markdown("**Detection settings**")
    minimum = st.slider("Minimum packets / second", 10, 500, 40, 5)
    multiplier = st.slider("Baseline multiplier", 1.5, 8.0, 3.0, 0.5)
    st.caption("Flags seconds above both thresholds, using the preceding 20 seconds (at least 5 required). Alerts are traffic heuristics, not confirmed attacks.")
    st.divider()
    st.caption("LOCAL ANALYSIS · HEADER METADATA ONLY")

st.caption("OBSERVE / UNDERSTAND / INVESTIGATE")
st.title("Your network, in focus.")
st.markdown("Explore the packets behind every connection. Track protocols, inspect headers, and spot unusual bursts.")


@st.fragment(run_every="1s")
def dashboard():
    capture.touch()
    records, total, errors = capture.snapshot()
    state = "CAPTURING" if capture.running else "PAUSED" if records else "READY"
    st.caption(f"● {state}   /   {capture.mode.upper()}   /   Times shown in UTC")
    if capture.mode == "Demo":
        st.info("Demo environment · Synthetic packets with two seeded traffic spikes. Press Start to stream more.", icon="🧪")
    if capture.error:
        st.error(capture.error)
    if not records:
        st.info("Start a capture or import a PCAP file to explore traffic.")
        return
    frame = pd.DataFrame(records)
    series = traffic_series(frame)
    # Last bucket may be incomplete. It is shown, but never classified as a spike.
    alerts = detect_spikes(series.iloc[:-1], minimum, multiplier)
    cols = st.columns(4)
    cols[0].metric("Packets observed", f"{total:,}")
    cols[1].metric("Retained traffic", f"{frame.length.sum() / 1_000_000:.2f} MB")
    cols[2].metric("Source addresses", frame.source.nunique())
    cols[3].metric("Spike alerts", len(alerts))
    st.caption(f"Showing {len(frame):,} retained headers · {max(0, total-len(frame)):,} older records evicted · {errors:,} decode errors")
    overview, packets, alert_tab, learn = st.tabs(["Traffic overview", "Packet explorer", "Spike alerts", "OSI field guide"])
    with overview:
        left, right = st.columns([2.2, 1])
        with left:
            st.subheader("Traffic pulse")
            fig = px.area(series.reset_index(), x="time", y="packets", color_discrete_sequence=["#35D6B4"], labels={"time": "Time (UTC)", "packets": "Packets / second"})
            fig.update_layout(height=300, margin=dict(l=0, r=0, t=15, b=0))
            st.plotly_chart(fig, use_container_width=True)
        with right:
            st.subheader("Protocol mix")
            counts = frame.protocol.value_counts().rename_axis("protocol").reset_index(name="packets")
            fig = px.pie(counts, names="protocol", values="packets", hole=.72, color_discrete_sequence=["#35D6B4", "#669BFF", "#B99AFF", "#FFC773", "#F17FA6", "#80CBDD"])
            fig.update_layout(height=300, margin=dict(l=0, r=0, t=15, b=0), legend=dict(orientation="h"))
            st.plotly_chart(fig, use_container_width=True)
        left, right = st.columns(2)
        with left:
            st.subheader("Most active sources")
            top = frame.groupby("source").agg(packets=("id", "size"), bytes=("length", "sum")).sort_values("bytes", ascending=False).head(8)
            st.dataframe(top, use_container_width=True)
        with right:
            st.subheader("DNS activity")
            dns = frame[frame.protocol == "DNS"]
            st.dataframe(dns[["time_utc", "source", "dns_query", "dns_direction"]].tail(8), hide_index=True, use_container_width=True)
    with packets:
        left, right = st.columns([1, 2])
        selected = left.multiselect("Protocols", sorted(frame.protocol.unique()))
        search = right.text_input("Find an address or DNS name", placeholder="192.168.1.12 or example.com")
        filtered = frame[frame.protocol.isin(selected)] if selected else frame
        if search:
            mask = pd.concat([filtered[c].str.contains(search, case=False, regex=False) for c in ["source", "destination", "dns_query"]], axis=1).any(axis=1)
            filtered = filtered[mask]
        columns = ["id", "time_utc", "source", "destination", "protocol", "source_port", "destination_port", "length", "tcp_flags", "dns_query"]
        st.caption(f"{len(filtered):,} matching packets · Table shows the latest 500")
        st.dataframe(filtered[columns].tail(500).iloc[::-1], hide_index=True, use_container_width=True)
        a, b = st.columns(2)
        # Quoting all fields prevents delimiters in packet metadata from creating extra CSV cells.
        # Prefix formula-leading strings for spreadsheet-safe CSV exports.
        export = filtered.copy()
        for column in export.columns:
            export[column] = export[column].map(lambda v: "'" + v if isinstance(v, str) and v.startswith(("=", "+", "-", "@", "\t", "\r", "\n")) else v)
        a.download_button("↓ Export filtered CSV", export.to_csv(index=False), "netpulse-packets.csv", "text/csv", use_container_width=True)
        b.download_button("↓ Export filtered JSONL", filtered.to_json(orient="records", lines=True), "netpulse-packets.jsonl", "application/x-ndjson", use_container_width=True)
        if not filtered.empty:
            packet_id = st.selectbox("Inspect packet ID (latest 500)", filtered.id.tail(500).iloc[::-1])
            record = filtered[filtered.id == packet_id].iloc[0]
            st.markdown(f"**Decoded path:** {record['layers']}")
            st.json(record.to_dict(), expanded=True)
    with alert_tab:
        st.subheader("Unusual traffic bursts")
        st.caption("Traffic charts and detection cover the latest hour of retained traffic, independent of explorer filters. The newest second is excluded. Alerts may change as the buffer rolls over.")
        if alerts.empty:
            st.success("No spikes above the current thresholds.")
        else:
            st.warning(f"{len(alerts)} high-volume seconds detected. Investigate the corresponding packet timestamps.")
            st.dataframe(alerts.sort_index(ascending=False), use_container_width=True)
            st.download_button("↓ Export alerts", alerts.to_csv(), "netpulse-alerts.csv", "text/csv")
    with learn:
        st.subheader("From a frame to a conversation")
        st.table(pd.DataFrame([
            ["7 · Application", "DNS / DHCP", "DNS names and direction; DHCP message types"],
            ["6 · Presentation", "Encoding and encryption", "Not independently inferred; encrypted payloads are not decrypted"],
            ["5 · Session", "Session management", "Not independently inferred from individual headers"],
            ["4 · Transport", "TCP / UDP", "Source and destination ports, TCP flags"],
            ["3 · Network", "IPv4 / IPv6 / ICMP", "IP addresses, TTL/hop limit, ICMP type"],
            ["2 · Data link", "Ethernet / 802.1Q / ARP", "Frame encapsulation, VLAN IDs and address resolution"],
            ["1 · Physical", "Signals and media", "Not observable through this packet capture API"],
        ], columns=["OSI layer", "Protocols / role", "What NetPulse shows"]))
        st.markdown("**Reading TCP flags:** `S` starts a connection, `A` acknowledges data, `F` closes gracefully, `R` resets, and `P` requests prompt delivery. UDP has no connection handshake. ICMP carries network control and diagnostic messages; it does not use TCP/UDP ports.")
        st.caption("DNS is counted as an application protocol; its UDP/TCP transport remains visible in the decoded layer path. Port 443 alone does not prove a particular application protocol.")


dashboard()
