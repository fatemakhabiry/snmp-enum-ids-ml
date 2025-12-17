import pandas as pd

# ---------- CONFIG ----------
# Name of the packets CSV exported by tshark
# If you used "packets.csv" instead of "packets_big.csv", change this line.
PACKETS_CSV = "packets_bigg.csv"
OUTPUT_CSV = "snmp_flow_dataset2.csv"
# ----------------------------

print(f"[+] Reading packets from {PACKETS_CSV} ...")
df = pd.read_csv(PACKETS_CSV, engine="python")

# Convert to numeric where needed
for col in ["udp.srcport", "udp.dstport", "ip.ttl",
            "frame.time_relative", "frame.len"]:
    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

# Keep only packets where there is a UDP port (real UDP traffic)
df = df[(df["udp.srcport"] > 0) | (df["udp.dstport"] > 0)]

print(f"[+] Total UDP packets: {len(df)}")

# Create a flow ID: srcip:srcport -> dstip:dstport
df["flow"] = (
    df["ip.src"].astype(str) + ":" + df["udp.srcport"].astype(str)
    + " -> " +
    df["ip.dst"].astype(str) + ":" + df["udp.dstport"].astype(str)
)

flows = []

for flow_id, g in df.groupby("flow"):
    srcip = g["ip.src"].iloc[0]
    dstip = g["ip.dst"].iloc[0]

    # Packets from src -> dst
    src_packets = g[g["ip.src"] == srcip]
    # Packets from dst -> src (reverse direction), if any
    dst_packets = g[g["ip.src"] == dstip]

    # TTL and bytes for each direction
    sttl = src_packets["ip.ttl"].mean()
    sbytes = src_packets["frame.len"].sum()

    if dst_packets.empty:
        # No reverse packets: copy sttl and set dbytes=0
        dttl = sttl
        dbytes = 0
    else:
        dttl = dst_packets["ip.ttl"].mean()
        dbytes = dst_packets["frame.len"].sum()

    # Duration of the flow
    dur = g["frame.time_relative"].max() - g["frame.time_relative"].min()

    # Is this flow SNMP? (port 161 on either side)
    is_snmp = ((g["udp.dstport"] == 161) | (g["udp.srcport"] == 161)).any()
    service = "snmp" if is_snmp else "other"
    label = 1 if is_snmp else 0

    flow_row = {
        "srcip": srcip,
        "srcport": g["udp.srcport"].iloc[0],
        "dstip": dstip,
        "dstport": g["udp.dstport"].iloc[0],
        "proto": "udp",
        "dur": dur,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "sttl": sttl,
        "dttl": dttl,
        "service": service,
        "Label": label,
    }

    flows.append(flow_row)

df_flows = pd.DataFrame(flows)

print("\n[+] Sample of final flow dataset:")
print(df_flows.head())

print("\n[+] Label counts (0 = normal, 1 = SNMP attack):")
print(df_flows["Label"].value_counts())

df_flows.to_csv(OUTPUT_CSV, index=False)
print(f"\n[+] Saved flow dataset to {OUTPUT_CSV}")

