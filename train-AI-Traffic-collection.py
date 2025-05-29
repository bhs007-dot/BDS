import numpy as np
from sklearn.ensemble import IsolationForest
import pickle

data = []
with open('traffic_data.csv', 'r') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) != 3:
            continue
        try:
            src_port = int(parts[0])
            dst_port = int(parts[1])
            pkt_len = int(parts[2])
            data.append([src_port, dst_port, pkt_len])
        except:
            continue

X = np.array(data)
if len(X) == 0:
    print("No valid data found in traffic_data.csv!")
    exit(1)

model = IsolationForest(contamination=0.01, random_state=42)
model.fit(X)

with open('traffic_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Model trained and saved as traffic_model.pkl")
