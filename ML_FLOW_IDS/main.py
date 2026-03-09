# main.py

import argparse
import joblib
from feature_adapter import adapt_features
from predict import predict_flows

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", required=True)
    parser.add_argument("-m", "--model", required=True)
    parser.add_argument("--scaler", required=True)
    parser.add_argument("--force-alert", action="store_true")
    args = parser.parse_args()

    model = joblib.load(args.model)
    scaler = joblib.load(args.scaler)

    flows = generate_flow_dataframe(
        args.pcap,
        bidirectional=True,
        flow_timeout=120000
    )

    X = adapt_features(flows, scaler)
    preds, confs = predict_flows(model, X)

    for i, (p, c) in enumerate(zip(preds, confs)):
        if p == 0 or args.force_alert:
            f = flows.iloc[i]
            print(
                f"[ALERT] Flow {f['Src IP']}:{f['Src Port']} -> "
                f"{f['Dst IP']}:{f['Dst Port']} | ATTACK | confidence={c:.2f}"
            )

if __name__ == "__main__":
    main()
