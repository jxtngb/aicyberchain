import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib

# Load raw data
df = pd.read_csv("traffic_data.csv")

# Encode protocol ONCE
df["protocol"] = df["protocol"].astype("category").cat.codes

# Save feature list
FEATURE_COLUMNS = ["protocol", "packet_size"]

# Scale packet_size
scaler = StandardScaler()
df["packet_size"] = scaler.fit_transform(df[["packet_size"]])

# Save scaler
joblib.dump(scaler, "scaler.pkl")

# Save processed data
df.to_csv("processed_data.csv", index=False)

print("✅ Data preprocessing complete")
