import pandas as pd
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv("processed_data.csv")

# Fake labels for learning (demo)
df["attack"] = (df["packet_size"] > 1).astype(int)

X = df.drop("attack", axis=1)
y = df["attack"]

model = RandomForestClassifier()
model.fit(X, y)

predictions = model.predict(X)
print("Detected attacks:", sum(predictions))
