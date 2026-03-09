# feature_adapter.py

import pandas as pd
import numpy as np
from feature_schema import CICIDS_FEATURES

MIN_PACKETS = 10

def adapt_features(flow_df, scaler):
    # Drop label if present
    if "Label" in flow_df.columns:
        flow_df = flow_df.drop(columns=["Label"])

    # Drop micro-flows
    flow_df = flow_df[flow_df["Total Fwd Packets"] +
                       flow_df["Total Backward Packets"] >= MIN_PACKETS]

    if flow_df.empty:
        raise RuntimeError("All flows dropped (<10 packets). No CICIDS-valid flows.")

    # Enforce feature order from scaler
    expected = list(scaler.feature_names_in_)
    flow_df = flow_df[expected]

    # Type safety
    flow_df = flow_df.replace([np.inf, -np.inf], 0).fillna(0)

    return scaler.transform(flow_df)
