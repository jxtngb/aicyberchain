from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd

from threat_app.ml.csv_upload_features import engineer_csv_features


BASE_DIR = Path(__file__).resolve().parent
MODEL_BUNDLE_PATH = BASE_DIR / "ml" / "csv_upload_model_bundle.pkl"

_bundle_cache = None


def _load_bundle():
    global _bundle_cache
    if _bundle_cache is not None:
        return _bundle_cache
    if not MODEL_BUNDLE_PATH.exists():
        return None
    _bundle_cache = joblib.load(MODEL_BUNDLE_PATH)
    return _bundle_cache


def csv_upload_model_ready() -> bool:
    return _load_bundle() is not None


def csv_upload_model_version() -> str:
    bundle = _load_bundle()
    if not bundle:
        return "legacy-rf-v1"
    return str(bundle.get("model_version", "csv-rf-v1"))


def _predict_with_autoencoder(bundle, feature_df: pd.DataFrame) -> Dict[str, Any]:
    ae_bundle = bundle.get("autoencoder")
    if not ae_bundle:
        return {"enabled": False}

    numeric_columns = ae_bundle["numeric_columns"]
    imputer = ae_bundle["imputer"]
    scaler = ae_bundle["scaler"]
    model = ae_bundle["model"]
    threshold = float(ae_bundle["threshold"])

    numeric_df = feature_df.reindex(columns=numeric_columns)
    transformed = imputer.transform(numeric_df)
    transformed = scaler.transform(transformed)
    reconstructed = model.predict(transformed)
    error = float(((transformed - reconstructed) ** 2).mean(axis=1)[0])
    attack = error >= threshold

    ratio = error / max(threshold, 1e-9)
    confidence = round(min(99.0, max(1.0, ratio * 100.0)), 2)
    return {
        "enabled": True,
        "attack": attack,
        "error": round(error, 6),
        "threshold": round(threshold, 6),
        "confidence": confidence,
    }


def _prepare_feature_frame(bundle, df: pd.DataFrame) -> pd.DataFrame:
    feature_columns = bundle["feature_columns"]
    if bundle.get("engineered_features"):
        prepared = engineer_csv_features(df.copy())
        return prepared.reindex(columns=feature_columns)
    return df.reindex(columns=feature_columns)


def _predict_core(bundle, df: pd.DataFrame) -> list[Dict[str, Any]]:
    pipeline = bundle.get("pipeline")
    threshold = float(bundle.get("threshold", 0.9))
    prepared = _prepare_feature_frame(bundle, df)

    rf_prob_series = None
    rf_attack_series = None
    if pipeline is not None:
        rf_prob_series = pipeline.predict_proba(prepared)[:, 1]
        rf_attack_series = rf_prob_series >= threshold

    proto_series = pd.to_numeric(prepared.get("protocol", pd.Series([99] * len(prepared))), errors="coerce").fillna(99)
    pkt_series = pd.to_numeric(prepared.get("packet_size", pd.Series([0] * len(prepared))), errors="coerce").fillna(0)

    ae_enabled = False
    ae_attack_series = np.zeros(len(prepared), dtype=bool)
    ae_error_series = np.full(len(prepared), np.nan)
    ae_threshold_value = None
    ae_conf_series = np.full(len(prepared), np.nan)

    ae_bundle = bundle.get("autoencoder")
    if ae_bundle:
        low_risk_mask = (
            proto_series.isin([1, 6, 17])
            & pkt_series.between(60, 1450, inclusive="both")
            & (
                pd.Series(rf_prob_series, index=prepared.index).lt(0.35)
                if rf_prob_series is not None
                else True
            )
        )
        use_mask = ~low_risk_mask
        if use_mask.any():
            numeric_columns = ae_bundle["numeric_columns"]
            imputer = ae_bundle["imputer"]
            scaler = ae_bundle["scaler"]
            model = ae_bundle["model"]
            ae_threshold_value = float(ae_bundle["threshold"])

            numeric_df = prepared.loc[use_mask].reindex(columns=numeric_columns)
            transformed = imputer.transform(numeric_df)
            transformed = scaler.transform(transformed)
            reconstructed = model.predict(transformed)
            errors = ((transformed - reconstructed) ** 2).mean(axis=1)
            ae_enabled = True
            ae_error_series[use_mask.to_numpy()] = errors
            ae_attack_series[use_mask.to_numpy()] = errors >= ae_threshold_value
            ratios = errors / max(ae_threshold_value, 1e-9)
            ae_conf_series[use_mask.to_numpy()] = np.clip(ratios * 100.0, 1.0, 99.0)

    support_threshold = float(bundle.get("autoencoder_support_threshold", 0.35))
    results = []
    for idx in range(len(prepared)):
        rf_prob = float(rf_prob_series[idx]) if rf_prob_series is not None else None
        rf_attack = bool(rf_attack_series[idx]) if rf_attack_series is not None else False
        proto = int(proto_series.iloc[idx])
        pkt = float(pkt_series.iloc[idx])
        ae_used = bool(ae_enabled and not np.isnan(ae_error_series[idx]))
        ae_attack = bool(ae_attack_series[idx]) if ae_used else False
        is_attack = rf_attack or (
            ae_attack and (
                rf_prob is None
                or rf_prob >= support_threshold
                or proto not in (1, 6, 17)
                or pkt > 1450
                or pkt < 60
            )
        )

        confidence_candidates = []
        if rf_prob is not None:
            confidence_candidates.append(round(rf_prob * 100.0, 2))
        if ae_used and not np.isnan(ae_conf_series[idx]):
            confidence_candidates.append(float(round(ae_conf_series[idx], 2)))
        confidence = max(confidence_candidates) if confidence_candidates else 50.0

        detectors = []
        if rf_prob is not None:
            detectors.append("random_forest")
        if ae_used:
            detectors.append("autoencoder")

        results.append(
            {
                "result": "Attack" if is_attack else "Normal",
                "confidence": round(confidence, 2),
                "threshold": threshold,
                "model_version": bundle.get("model_version", "csv-rf-v1"),
                "detectors": detectors,
                "rf_probability": round(rf_prob, 6) if rf_prob is not None else None,
                "autoencoder_used": ae_used,
                "autoencoder_error": round(float(ae_error_series[idx]), 6) if ae_used else None,
                "autoencoder_threshold": round(float(ae_threshold_value), 6) if ae_used and ae_threshold_value is not None else None,
            }
        )
    return results


def predict_csv_rows(rows_df: pd.DataFrame) -> list[Dict[str, Any]]:
    bundle = _load_bundle()
    if bundle is None:
        raise RuntimeError("CSV upload model is not trained yet.")
    return _predict_core(bundle, rows_df)


def predict_csv_row(row: Dict[str, Any]) -> Dict[str, Any]:
    bundle = _load_bundle()
    if bundle is None:
        raise RuntimeError("CSV upload model is not trained yet.")
    return _predict_core(bundle, pd.DataFrame([row]))[0]
