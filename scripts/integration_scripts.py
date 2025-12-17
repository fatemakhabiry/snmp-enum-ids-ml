import glob
import pandas as pd
import os

DATA_DIR = "data"
OUTPUT_FILE = "snmp_merged_dataset.csv"

# Load all CSV files
files = glob.glob(os.path.join(DATA_DIR, "*.csv"))

if not files:
    raise SystemExit("❌ No CSV files found in data folder")

dfs = []
for f in files:
    df = pd.read_csv(f)
    df["source_file"] = os.path.basename(f)
    dfs.append(df)

data = pd.concat(dfs, ignore_index=True)

print("✔ Files merged:", len(files))
print("✔ Total rows before cleaning:", len(data))

# Required columns
required_cols = [
    "srcip","srcport","dstip","dstport","proto",
    "dur","sbytes","dbytes","sttl","dttl","service","Label"
]

missing = [c for c in required_cols if c not in data.columns]
if missing:
    raise SystemExit(f"❌ Missing columns: {missing}")

# Convert numeric columns
num_cols = ["srcport","dstport","dur","sbytes","dbytes","sttl","dttl","Label"]
for c in num_cols:
    data[c] = pd.to_numeric(data[c], errors="coerce")

# Drop invalid rows
data = data.dropna(subset=num_cols)

data["srcport"] = data["srcport"].astype(int)
data["dstport"] = data["dstport"].astype(int)
data["Label"] = data["Label"].astype(int)

# Remove duplicates
before = len(data)
data = data.drop_duplicates()
after = len(data)
print("✔ Duplicates removed:", before - after)

# Keep UDP only
data = data[data["proto"].str.lower() == "udp"]

# Save merged dataset
data.to_csv(OUTPUT_FILE, index=False)
print("✔ Final dataset saved as:", OUTPUT_FILE)

print("\nLabel distribution:")
print(data["Label"].value_counts())
