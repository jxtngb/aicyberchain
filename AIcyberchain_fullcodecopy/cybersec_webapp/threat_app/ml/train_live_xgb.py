from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from threat_app.ml.live_xgb_features import build_live_feature_dict

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover - runtime environment may not have xgboost installed
    XGBClassifier = None


def _find_label_column(columns):
    candidates = ["Label", "label", "Class", "class", "attack", "Attack", "attack_type", "Attack Type"]
    for candidate in candidates:
        if candidate in columns:
            return candidate
    raise ValueError("Could not find a label column for live XGBoost training.")


def _build_training_frame(df):
    protocol_col = next((c for c in ("protocol", "Protocol", "proto") if c in df.columns), None)
    packet_col = next(
        (c for c in ("packet_size", "Packet Length", "Length", "length", "Pkt Size Avg", "TotLen Fwd Pkts") if c in df.columns),
        None,
    )

    if not protocol_col or not packet_col:
        raise ValueError("Dataset must include protocol and packet-size-like columns.")

    protocol_text = df[protocol_col].fillna("OTHER").astype(str).str.upper().str.split().str[0].str.replace("/", "", regex=False)
    protocol_map = {
        "TCP": 6,
        "UDP": 17,
        "ICMP": 1,
        "HTTP": 6,
        "HTTPS": 6,
        "TLS": 6,
        "TLSV1.2": 6,
        "TLSV1.3": 6,
        "FTP": 6,
        "SSH": 6,
        "SMTP": 6,
        "DNS": 17,
        "QUIC": 17,
        "IGMP": 2,
        "ARP": 0,
        "LLDP": 0,
    }
    protocol = pd.to_numeric(protocol_text, errors="coerce").fillna(protocol_text.map(protocol_map)).fillna(99).astype(int)
    packet_size = pd.to_numeric(df[packet_col], errors="coerce").fillna(0.0)

    if "src" in df.columns:
        burst_count = df.groupby(df["src"].fillna("unknown")).cumcount() + 1
        burst_count = burst_count.clip(upper=50)
    else:
        burst_count = pd.Series(np.ones(len(df), dtype=int), index=df.index)

    feature_rows = [
        build_live_feature_dict(proto, pkt, int(burst), window_seconds=20)
        for proto, pkt, burst in zip(protocol, packet_size, burst_count)
    ]
    return pd.DataFrame(feature_rows)


def main():
    parser = argparse.ArgumentParser(description="Train optional XGBoost model for live packet monitoring.")
    parser.add_argument("--data", required=True, help="Path to training CSV")
    parser.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parent / "live_xgb_model.pkl"),
        help="Output path for trained live-monitor XGBoost model",
    )
    args = parser.parse_args()

    if XGBClassifier is None:
        raise RuntimeError("xgboost is not installed. Install xgboost before training the live-monitor model.")

    data_path = Path(args.data).resolve()
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Loading dataset: {data_path}")
    df = pd.read_csv(data_path, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]

    label_col = _find_label_column(df.columns.tolist())
    y_raw = df[label_col].astype(str).str.strip().str.lower()
    benign_values = {"benign", "normal", "0", "false", "legitimate"}
    y = (~y_raw.isin(benign_values)).astype(int)

    X = _build_training_frame(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = XGBClassifier(
        n_estimators=120,
        max_depth=4,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=1,
    )

    print("[INFO] Training XGBoost model...")
    model.fit(X_train, y_train)

    prob = model.predict_proba(X_test)[:, 1]
    pred = (prob >= 0.5).astype(int)

    print("\n[REPORT] Classification report")
    print(classification_report(y_test, pred, digits=4))
    try:
        print(f"[REPORT] ROC-AUC: {roc_auc_score(y_test, prob):.4f}")
    except Exception:
        print("[REPORT] ROC-AUC: N/A")

    bundle = {
        "model": model,
        "feature_columns": X.columns.tolist(),
        "model_version": "live-xgb-v1",
    }
    joblib.dump(bundle, out_path)
    print(f"[OK] Saved model: {out_path}")


if __name__ == "__main__":
    main()
