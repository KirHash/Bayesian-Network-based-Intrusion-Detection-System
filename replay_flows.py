"""
Demo traffic source: appends held-out flows to a CSV in small batches,
the way a flow exporter would, so live_monitor.py has something to read.

    python replay_flows.py live_flows.csv [batches] [batch_size]
"""
import sys
import time

from data_loader import load_all, train_val_test_split

path = sys.argv[1]

batches = int(sys.argv[2]) if len(sys.argv) > 2 else 10

size = int(sys.argv[3]) if len(sys.argv) > 3 else 200

_, _, test = train_val_test_split(load_all())

flows = test.sample(batches * size, random_state=1)

# The exporter would not know the answer
print("Replaying label mix:", flows["Label"].value_counts().to_dict())

flows = flows.drop(columns="Label")

with open(path, "w", newline="") as f:

    flows.iloc[:0].to_csv(f, index=False)

for i in range(batches):

    with open(path, "a", newline="") as f:

        flows.iloc[i * size:(i + 1) * size].to_csv(
            f, index=False, header=False
        )

    print(f"wrote batch {i + 1}/{batches}", flush=True)

    time.sleep(2)
