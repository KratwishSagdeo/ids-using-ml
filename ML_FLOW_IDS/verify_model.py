import joblib
import numpy as np
from feature_schema import FEATURE_COLUMNS, EXPECTED_FEATURE_COUNT

print("=== FEATURE SCHEMA ===")
print("Feature count:", EXPECTED_FEATURE_COUNT)
print("First 5 features:", FEATURE_COLUMNS[:5])
print("Last 5 features:", FEATURE_COLUMNS[-5:])

print("\n=== LOADING MODEL ===")
model = joblib.load("my_model.pkl")
print("Model type:", type(model))

print("\n=== MODEL FEATURE CHECK ===")
if hasattr(model, "n_features_in_"):
    print("Model expects:", model.n_features_in_)
    assert model.n_features_in_ == EXPECTED_FEATURE_COUNT
else:
    print("Model does not expose n_features_in_ (OK)")

print("\n=== LOADING SCALER ===")
scaler = joblib.load("scaler.pkl")
print("Scaler type:", type(scaler))

if hasattr(scaler, "n_features_in_"):
    print("Scaler expects:", scaler.n_features_in_)
    assert scaler.n_features_in_ == EXPECTED_FEATURE_COUNT
else:
    print("Scaler does not expose n_features_in_ (OK)")

print("\n=== DUMMY PREDICTION TEST ===")
X = np.zeros((1, EXPECTED_FEATURE_COUNT), dtype=np.float32)

X_scaled = scaler.transform(X)
y = model.predict(X_scaled)

print("Prediction output:", y)

if hasattr(model, "predict_proba"):
    probs = model.predict_proba(X_scaled)
    print("Probabilities:", probs)

print("\n✅ MODEL + SCALER + FEATURES ARE COMPATIBLE")
