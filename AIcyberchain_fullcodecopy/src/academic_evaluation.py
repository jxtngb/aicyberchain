from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPRegressor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


BENIGN_VALUES = {"benign", "normal", "0", "false", "legitimate"}
LABEL_CANDIDATES = ["Label", "label", "Class", "class", "attack", "Attack"]


@dataclass
class MetricSet:
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float | None = None


def find_label_column(columns: list[str]) -> str:
    for name in LABEL_CANDIDATES:
        if name in columns:
            return name
    raise ValueError(f"Could not find a label column. Expected one of: {', '.join(LABEL_CANDIDATES)}")


def normalize_protocol(series: pd.Series) -> pd.Series:
    numeric = pd.to_numeric(series, errors="coerce")
    if numeric.notna().any():
        return numeric.fillna(-1).astype(int)

    mapping = {"icmp": 1, "tcp": 6, "udp": 17}
    return series.astype(str).str.strip().str.lower().map(mapping).fillna(-1).astype(int)


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    features = df.copy()

    if "protocol" in features.columns:
        proto = normalize_protocol(features["protocol"])
        features["protocol"] = proto
        features["is_common_protocol"] = proto.isin([1, 6, 17]).astype(int)
        features["is_icmp"] = (proto == 1).astype(int)
        features["is_tcp"] = (proto == 6).astype(int)
        features["is_udp"] = (proto == 17).astype(int)

    if "packet_size" in features.columns:
        pkt = pd.to_numeric(features["packet_size"], errors="coerce")
        features["packet_size"] = pkt
        features["packet_size_small"] = (pkt < 60).astype(int)
        features["packet_size_large"] = (pkt > 1400).astype(int)
        features["packet_size_log"] = np.log1p(pkt.clip(lower=0))

    for port_col in ("src_port", "source_port", "sport", "dst_port", "destination_port", "dport"):
        if port_col in features.columns:
            port = pd.to_numeric(features[port_col], errors="coerce")
            features[port_col] = port
            features[f"{port_col}_well_known"] = ((port >= 0) & (port <= 1024)).astype(int)

    if "src_port" in features.columns and "dst_port" in features.columns:
        src_port = pd.to_numeric(features["src_port"], errors="coerce")
        dst_port = pd.to_numeric(features["dst_port"], errors="coerce")
        features["same_src_dst_port"] = (src_port == dst_port).astype(int)

    drop_cols = [c for c in ("source_ip", "destination_ip", "src_ip", "dst_ip", "Timestamp", "timestamp") if c in features.columns]
    if drop_cols:
        features = features.drop(columns=drop_cols)

    return features.replace([np.inf, -np.inf], np.nan)


def metric_set(y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray | None = None) -> MetricSet:
    roc = None
    if y_score is not None and len(np.unique(y_true)) > 1:
        try:
            roc = float(roc_auc_score(y_true, y_score))
        except Exception:
            roc = None
    return MetricSet(
        accuracy=float(accuracy_score(y_true, y_pred)),
        precision=float(precision_score(y_true, y_pred, zero_division=0)),
        recall=float(recall_score(y_true, y_pred, zero_division=0)),
        f1_score=float(f1_score(y_true, y_pred, zero_division=0)),
        roc_auc=roc,
    )


def tune_autoencoder_threshold(errors: np.ndarray, y_true: np.ndarray) -> float:
    best_threshold = float(np.percentile(errors, 95))
    best_f1 = -1.0
    for percentile in np.linspace(80, 99.5, 40):
        threshold = float(np.percentile(errors, percentile))
        pred = (errors > threshold).astype(int)
        score = f1_score(y_true, pred, zero_division=0)
        if score > best_f1:
            best_f1 = score
            best_threshold = threshold
    return best_threshold


def build_random_forest_pipeline(X: pd.DataFrame) -> Pipeline:
    numeric_cols = X.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = [c for c in X.columns if c not in numeric_cols]

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", Pipeline([("imputer", SimpleImputer(strategy="median"))]), numeric_cols),
            (
                "cat",
                Pipeline(
                    [
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("onehot", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                categorical_cols,
            ),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        n_jobs=1,
        class_weight="balanced_subsample",
    )
    return Pipeline([("preprocess", preprocessor), ("model", model)])


def prepare_autoencoder_data(X_train: pd.DataFrame, X_val: pd.DataFrame, X_test: pd.DataFrame):
    numeric_cols = X_train.select_dtypes(include=[np.number]).columns.tolist()
    if not numeric_cols:
        raise ValueError("Autoencoder evaluation requires at least one numeric feature.")

    imputer = SimpleImputer(strategy="median")
    scaler = StandardScaler()

    train_num = imputer.fit_transform(X_train[numeric_cols])
    val_num = imputer.transform(X_val[numeric_cols])
    test_num = imputer.transform(X_test[numeric_cols])

    train_scaled = scaler.fit_transform(train_num)
    val_scaled = scaler.transform(val_num)
    test_scaled = scaler.transform(test_num)

    return train_scaled.astype(np.float32), val_scaled.astype(np.float32), test_scaled.astype(np.float32), numeric_cols


def train_autoencoder(X_train_normal: np.ndarray) -> MLPRegressor:
    input_size = X_train_normal.shape[1]
    hidden = max(4, min(32, input_size * 2))
    bottleneck = max(2, min(16, input_size // 2 if input_size > 2 else 2))
    model = MLPRegressor(
        hidden_layer_sizes=(hidden, bottleneck, hidden),
        activation="relu",
        solver="adam",
        alpha=1e-4,
        learning_rate_init=0.001,
        max_iter=400,
        random_state=42,
    )
    model.fit(X_train_normal, X_train_normal)
    return model


def reconstruction_error(model: MLPRegressor, X: np.ndarray) -> np.ndarray:
    recon = model.predict(X)
    return ((X - recon) ** 2).mean(axis=1)


def main():
    parser = argparse.ArgumentParser(description="Academic-quality evaluation for the project models.")
    parser.add_argument("--data", required=True, help="Path to training/evaluation CSV")
    parser.add_argument("--out-dir", default="report_artifacts", help="Directory to store metrics and trained autoencoder")
    parser.add_argument("--label-col", default="", help="Optional label column name override")
    args = parser.parse_args()

    data_path = Path(args.data).resolve()
    out_dir = (Path(__file__).resolve().parent / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(data_path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]

    label_col = args.label_col.strip() or find_label_column(df.columns.tolist())
    y_raw = df[label_col].astype(str).str.strip().str.lower()
    y = (~y_raw.isin(BENIGN_VALUES)).astype(int).to_numpy()

    X_raw = df.drop(columns=[label_col])
    X = engineer_features(X_raw)

    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.25, random_state=42, stratify=y_train_val
    )

    rf_pipeline = build_random_forest_pipeline(X_train)
    rf_pipeline.fit(X_train, y_train)
    rf_prob = rf_pipeline.predict_proba(X_test)[:, 1]
    rf_pred = (rf_prob >= 0.5).astype(int)
    rf_metrics = metric_set(y_test, rf_pred, rf_prob)

    ae_train, ae_val, ae_test, ae_features = prepare_autoencoder_data(X_train, X_val, X_test)
    normal_train = ae_train[y_train == 0]
    if len(normal_train) == 0:
        raise ValueError("Autoencoder training requires at least one normal sample in the training split.")

    autoencoder = train_autoencoder(normal_train)
    ae_model_path = out_dir / "autoencoder_v2.pkl"
    joblib.dump(autoencoder, ae_model_path)

    val_errors = reconstruction_error(autoencoder, ae_val)
    threshold = tune_autoencoder_threshold(val_errors, y_val)
    test_errors = reconstruction_error(autoencoder, ae_test)
    ae_pred = (test_errors > threshold).astype(int)
    ae_metrics = metric_set(y_test, ae_pred, test_errors)

    summary = {
        "dataset": str(data_path),
        "label_column": label_col,
        "split": {"train": int(len(X_train)), "validation": int(len(X_val)), "test": int(len(X_test))},
        "feature_count": int(X.shape[1]),
        "autoencoder_numeric_feature_count": int(len(ae_features)),
        "random_forest_test_metrics": asdict(rf_metrics),
        "autoencoder_test_metrics": asdict(ae_metrics),
        "autoencoder_threshold": threshold,
        "notes": [
            "Metrics are reported on a held-out test split.",
            "The autoencoder-style reconstruction model is trained on normal training samples only.",
            "Threshold is tuned on validation data instead of using mean+std directly.",
            "Engineered features extend beyond protocol and packet_size when relevant columns exist.",
            "This script improves academic evaluation and does not modify the deployed web runtime model.",
        ],
    }

    metrics_path = out_dir / "academic_metrics.json"
    metrics_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("[OK] Academic evaluation complete")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
