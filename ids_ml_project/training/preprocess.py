import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib

# Load
df = pd.read_csv("data/cicids2017.csv")

# 🔥 Strip spaces from column names
df.columns = df.columns.str.strip()

# Drop non-numeric / identifier columns
df = df.drop(
    columns=["Flow ID", "Source IP", "Destination IP", "Timestamp"],
    errors="ignore"
)

# Replace inf & nan
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# 🔥 Label encoding
df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Flow Packets/s",
    "Flow Bytes/s"
]

X = df[FEATURES]
y = df["Label"]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

joblib.dump(scaler, "training/scaler.pkl")

np.save("training/X.npy", X_scaled)
np.save("training/y.npy", y.values)

print("✅ Preprocessing done")
