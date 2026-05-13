from __future__ import annotations

from datetime import timedelta


def update_recent_activity(recent, observed_at, window_seconds=20):
    recent.append(observed_at)
    cutoff = observed_at - timedelta(seconds=window_seconds)
    while recent and recent[0] < cutoff:
        recent.popleft()
    return recent


def build_live_feature_dict(protocol, packet_size, burst_count, window_seconds=20):
    packet_rate = burst_count / float(window_seconds)
    return {
        "protocol": int(protocol),
        "packet_size": float(packet_size),
        "packet_rate": float(packet_rate),
        "burst_count": int(burst_count),
        "is_common_protocol": int(protocol in (1, 6, 17)),
        "icmp_large_packet": int(protocol == 1 and packet_size > 1000),
        "large_packet_flag": int(packet_size > 1450),
        "small_packet_flag": int(packet_size < 60),
    }
