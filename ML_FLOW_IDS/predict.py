# predict.py

import numpy as np

ATTACK = 0
BENIGN = 1

def predict_flows(model, X):
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)
        attack_conf = probs[:, ATTACK]
        preds = np.where(attack_conf >= 0.50, ATTACK, BENIGN)
    else:
        preds = model.predict(X)
        attack_conf = np.ones(len(preds)) * 0.99  # deterministic fallback

    return preds, attack_conf
