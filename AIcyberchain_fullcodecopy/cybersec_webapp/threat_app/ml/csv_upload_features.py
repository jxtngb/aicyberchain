from __future__ import annotations

import numpy as np
import pandas as pd


BENIGN_VALUES = {"benign", "normal", "0", "false", "legitimate"}
LABEL_CANDIDATES = ["Label", "label", "Class", "class", "attack", "Attack", "attack_type", "Attack Type"]


def find_label_column(columns):
    for candidate in LABEL_CANDIDATES:
        if candidate in columns:
            return candidate
    raise ValueError(
        "Could not find a label column. Expected one of: " + ", ".join(LABEL_CANDIDATES)
    )


def _coalesce_columns(df, canonical_name, aliases):
    if canonical_name in df.columns:
        return df

    for alias in aliases:
        if alias in df.columns:
            df[canonical_name] = df[alias]
            return df
    return df


def _normalize_protocol(series):
    numeric = pd.to_numeric(series, errors="coerce")
    if numeric.notna().any():
        return numeric.fillna(-1).astype(int)

    mapping = {
        "icmp": 1,
        "tcp": 6,
        "udp": 17,
        "http": 6,
        "https": 6,
        "tls": 6,
        "tlsv1.2": 6,
        "tlsv1.3": 6,
        "ftp": 6,
        "ssh": 6,
        "smtp": 6,
        "pop": 6,
        "imap": 6,
        "dns": 17,
        "dhcp": 17,
        "ntp": 17,
        "quic": 17,
        "igmp": 2,
        "arp": 0,
        "lldp": 0,
    }
    return (
        series.astype(str)
        .str.strip()
        .str.lower()
        .str.split()
        .str[0]
        .str.replace("/", "", regex=False)
        .map(mapping)
        .fillna(-1)
        .astype(int)
    )


def engineer_csv_features(df):
    features = df.copy()
    features.columns = [str(c).strip() for c in features.columns]

    features = _coalesce_columns(features, "protocol", ["Protocol", "proto"])
    features = _coalesce_columns(features, "packet_size", ["Length", "length", "Packet Length", "Pkt Size Avg", "TotLen Fwd Pkts"])
    features = _coalesce_columns(features, "src_port", ["Source Port", "source_port", "sport"])
    features = _coalesce_columns(features, "dst_port", ["Destination Port", "destination_port", "dport"])
    features = _coalesce_columns(features, "payload", ["Payload"])
    features = _coalesce_columns(features, "flags", ["Flags"])

    if "protocol" in features.columns:
        proto = _normalize_protocol(features["protocol"])
        features["protocol"] = proto
        features["is_common_protocol"] = proto.isin([1, 6, 17]).astype(int)
        features["is_icmp"] = (proto == 1).astype(int)
        features["is_tcp"] = (proto == 6).astype(int)
        features["is_udp"] = (proto == 17).astype(int)
    else:
        features["protocol"] = -1
        features["is_common_protocol"] = 0
        features["is_icmp"] = 0
        features["is_tcp"] = 0
        features["is_udp"] = 0

    if "packet_size" in features.columns:
        pkt = pd.to_numeric(features["packet_size"], errors="coerce")
    else:
        pkt = pd.Series(np.nan, index=features.index, dtype=float)
    features["packet_size"] = pkt
    features["packet_size_small"] = (pkt < 60).astype(int)
    features["packet_size_large"] = (pkt > 1400).astype(int)
    features["packet_size_log"] = np.log1p(pkt.clip(lower=0))

    for port_col in ("src_port", "dst_port"):
        if port_col in features.columns:
            port = pd.to_numeric(features[port_col], errors="coerce")
        else:
            port = pd.Series(np.nan, index=features.index, dtype=float)
        features[port_col] = port
        features[f"{port_col}_well_known"] = ((port >= 0) & (port <= 1024)).astype(int)

    features["same_src_dst_port"] = (features["src_port"] == features["dst_port"]).astype(int)

    flags = features.get("flags", pd.Series("", index=features.index)).astype(str).str.upper()
    features["tcp_syn_flag"] = flags.str.contains("SYN", regex=False).astype(int)
    features["tcp_ack_flag"] = flags.str.contains("ACK", regex=False).astype(int)
    features["tcp_fin_flag"] = flags.str.contains("FIN", regex=False).astype(int)

    payload = features.get("payload", pd.Series("", index=features.index))
    payload_text = payload.fillna("").astype(str)
    features["payload_length"] = payload_text.str.len()
    features["has_payload"] = (features["payload_length"] > 0).astype(int)
    features["icmp_large_packet"] = (
        (features["protocol"] == 1) & (features["packet_size"] > 1000)
    ).astype(int)

    drop_cols = [
        col
        for col in (
            "Source",
            "Source IP",
            "Src IP",
            "SrcIP",
            "source_ip",
            "Destination",
            "Destination IP",
            "Dst IP",
            "DstIP",
            "destination_ip",
            "src",
            "dst",
            "Timestamp",
            "timestamp",
            "length",
            "Length",
            "Packet Length",
            "Pkt Size Avg",
            "TotLen Fwd Pkts",
            "proto",
            "Protocol",
            "Payload",
            "Flags",
        )
        if col in features.columns
    ]
    if drop_cols:
        features = features.drop(columns=drop_cols)

    return features.replace([np.inf, -np.inf], np.nan)
