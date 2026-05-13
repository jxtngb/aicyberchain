from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPRegressor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from threat_app.ml.csv_upload_features import BENIGN_VALUES, engineer_csv_features, find_label_column


def _metric_line(name, y_true, y_pred, y_score=None):
    acc = (y_true == y_pred).mean()
    prec = 0.0
    rec = 0.0
    f1 = 0.0
    positives = y_pred.sum()
    actual = y_true.sum()
    if positives:
        prec = ((y_true == 1) & (y_pred == 1)).sum() / positives
    if actual:
        rec = ((y_true == 1) & (y_pred == 1)).sum() / actual
    if (prec + rec) > 0:
        f1 = 2 * prec * rec / (prec + rec)

    roc = "N/A"
    if y_score is not None and len(np.unique(y_true)) > 1:
        try:
            roc = f"{roc_auc_score(y_true, y_score):.4f}"
        except Exception:
            roc = "N/A"
    print(
        f"[REPORT] {name}: accuracy={acc:.4f} precision={prec:.4f} "
        f"recall={rec:.4f} f1={f1:.4f} roc_auc={roc}"
    )


def _prepare_autoencoder_sets(X_train, X_val, X_test):
    numeric_columns = X_train.select_dtypes(include=[np.number]).columns.tolist()
    if not numeric_columns:
        raise ValueError("Autoencoder training requires numeric engineered features.")

    imputer = SimpleImputer(strategy="median")
    scaler = StandardScaler()

    train_num = imputer.fit_transform(X_train[numeric_columns])
    val_num = imputer.transform(X_val[numeric_columns])
    test_num = imputer.transform(X_test[numeric_columns])

    train_scaled = scaler.fit_transform(train_num)
    val_scaled = scaler.transform(val_num)
    test_scaled = scaler.transform(test_num)
    return train_scaled, val_scaled, test_scaled, numeric_columns, imputer, scaler


def _train_autoencoder(normal_train):
    input_size = normal_train.shape[1]
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
    model.fit(normal_train, normal_train)
    return model


def _reconstruction_error(model, X):
    recon = model.predict(X)
    return ((X - recon) ** 2).mean(axis=1)


def _tune_threshold(errors, y_true):
    best_threshold = float(np.percentile(errors, 95))
    best_f1 = -1.0
    for percentile in np.linspace(80, 99.5, 40):
        threshold = float(np.percentile(errors, percentile))
        pred = (errors >= threshold).astype(int)
        score = f1_score(y_true, pred, zero_division=0)
        if score > best_f1:
            best_f1 = score
            best_threshold = threshold
    return best_threshold


def main():
    parser = argparse.ArgumentParser(description="Train dedicated CSV upload hybrid model.")
    parser.add_argument("--data", required=True, help="Path to training CSV file")
    parser.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parent / "csv_upload_model_bundle.pkl"),
        help="Output path for model bundle",
    )
    parser.add_argument("--threshold", type=float, default=0.85, help="Random Forest attack probability threshold")
    args = parser.parse_args()

    data_path = Path(args.data).resolve()
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Loading dataset: {data_path}")
    df = pd.read_csv(data_path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]

    label_col = find_label_column(df.columns.tolist())
    print(f"[INFO] Label column: {label_col}")

    y_raw = df[label_col].astype(str).str.strip().str.lower()
    y = (~y_raw.isin(BENIGN_VALUES)).astype(int)

    X_raw = df.drop(columns=[label_col]).copy()
    X = engineer_csv_features(X_raw)
    X = X.loc[:, ~X.columns.duplicated()]
    X = X.dropna(axis=1, how="all")

    numeric_cols = X.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = [c for c in X.columns if c not in numeric_cols]

    numeric_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
        ]
    )
    categorical_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_pipeline, numeric_cols),
            ("cat", categorical_pipeline, categorical_cols),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=260,
        random_state=42,
        n_jobs=1,
        class_weight="balanced_subsample",
    )

    pipeline = Pipeline(
        steps=[
            ("preprocess", preprocessor),
            ("model", model),
        ]
    )

    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.25, random_state=42, stratify=y_train_val
    )

    print("[INFO] Training Random Forest...")
    pipeline.fit(X_train, y_train)

    rf_test_prob = pipeline.predict_proba(X_test)[:, 1]
    rf_test_pred = (rf_test_prob >= args.threshold).astype(int)
    _metric_line("RandomForest(test)", y_test.to_numpy(), rf_test_pred, rf_test_prob)
    print("\n[REPORT] Classification report")
    print(classification_report(y_test, rf_test_pred, digits=4))

    train_scaled, val_scaled, test_scaled, ae_numeric_columns, ae_imputer, ae_scaler = _prepare_autoencoder_sets(
        X_train, X_val, X_test
    )
    normal_train = train_scaled[y_train.to_numpy() == 0]
    if len(normal_train) == 0:
        raise ValueError("No normal samples available for autoencoder training.")

    print("[INFO] Training autoencoder-style reconstruction model...")
    autoencoder = _train_autoencoder(normal_train)
    val_errors = _reconstruction_error(autoencoder, val_scaled)
    ae_threshold = _tune_threshold(val_errors, y_val.to_numpy())
    test_errors = _reconstruction_error(autoencoder, test_scaled)
    ae_test_pred = (test_errors >= ae_threshold).astype(int)
    _metric_line("Autoencoder(test)", y_test.to_numpy(), ae_test_pred, test_errors)

    hybrid_pred = np.logical_or(rf_test_pred == 1, ae_test_pred == 1).astype(int)
    hybrid_score = np.maximum(rf_test_prob, np.clip(test_errors / max(ae_threshold, 1e-9), 0.0, 1.0))
    _metric_line("Hybrid(test)", y_test.to_numpy(), hybrid_pred, hybrid_score)

    bundle = {
        "pipeline": pipeline,
        "feature_columns": X.columns.tolist(),
        "threshold": float(args.threshold),
        "autoencoder_support_threshold": 0.35,
        "engineered_features": True,
        "model_version": "csv-hybrid-v2",
        "decision_mode": "hybrid_or",
        "autoencoder": {
            "model": autoencoder,
            "imputer": ae_imputer,
            "scaler": ae_scaler,
            "numeric_columns": ae_numeric_columns,
            "threshold": float(ae_threshold),
        },
    }
    joblib.dump(bundle, out_path)
    print(f"[OK] Saved model bundle: {out_path}")


if __name__ == "__main__":
    main()
