import threading  # Used to run packet capture in a background thread.
import time  # Used for short sleeps after capture failures.
from collections import defaultdict, deque  # Efficient fixed-size buffers for live state.
from pathlib import Path  # Used to resolve the optional live XGBoost model path.

import joblib  # Used to load the optional live XGBoost model bundle.
import pandas as pd  # Used to build one-row feature tables for optional XGBoost inference.
from scapy.all import sniff, IP  # Scapy provides packet sniffing and IP-layer access.
from django.utils.timezone import now  # Django-aware current timestamp helper.
from datetime import timedelta  # Used to define rolling time windows.
from threat_app.ml.live_xgb_features import build_live_feature_dict, update_recent_activity  # Shared feature builder for training and runtime.
from threat_app.models import Threat  # Django model where observed packets are stored.
from threat_app.ti_enrichment import enrich_ip  # Local IP enrichment helper for dashboard snapshots.

monitor_thread = None  # Holds the background thread object once monitoring starts.
monitor_running = False  # Global flag that controls whether the sniff loop should keep running.
monitor_lock = threading.Lock()  # Protects shared live-monitor state from concurrent access.
LAST_MONITOR_ERROR = ""  # Stores the last packet-capture error status for UI or diagnostics.

# Live-monitor-only state kept in memory for dashboard summaries.
LIVE_EVENT_BUFFER = deque(maxlen=500)  # Recent live events shown in the monitoring snapshot.
SOURCE_ACTIVITY = defaultdict(lambda: deque(maxlen=400))  # Per-source rolling timestamp history used for rate scoring.
LIVE_PACKET_COUNT = 0  # Total number of packets processed since the monitor started.
LIVE_XGB_MODEL_PATH = Path(__file__).resolve().parent / "ml" / "live_xgb_model.pkl"  # Optional model bundle path for second-stage live inference.


def _load_live_xgb_bundle():
    if not LIVE_XGB_MODEL_PATH.exists():
        return None
    try:
        return joblib.load(LIVE_XGB_MODEL_PATH)
    except Exception:
        return None


LIVE_XGB_BUNDLE = _load_live_xgb_bundle()  # Load the optional XGBoost bundle once so capture stays low-latency.


def _live_monitor_infer(source_ip, protocol, packet_size, observed_at):
    """
    Lightweight live monitor model:
    - Returns operational signal levels only (no Attack verdict)
    - Uses protocol, packet size, and short-window source activity
    """
    recent = SOURCE_ACTIVITY[source_ip]  # Fetch the rolling timestamp buffer for this source IP.
    window_seconds = 20  # Evaluate burst activity over the last 20 seconds.
    update_recent_activity(recent, observed_at, window_seconds=window_seconds)  # Record the packet and drop stale timestamps.

    burst_count = len(recent)  # Reuse the rolling count as a burst feature for both heuristic and XGBoost paths.
    features = build_live_feature_dict(protocol, packet_size, burst_count, window_seconds=window_seconds)  # Build the shared feature set.
    rate = features["packet_rate"]  # Compute packets-per-second for this source within the window.

    score = 0.06  # Start from a low baseline anomaly score.
    if protocol not in (1, 6, 17):  # Penalize uncommon protocols outside ICMP, TCP, and UDP.
        score += 0.22  # Add extra anomaly weight for uncommon protocol usage.
    if packet_size > 1450:  # Jumbo or near-MTU packet sizes may indicate noisy or unusual traffic.
        score += 0.28  # Increase the anomaly score for large packets.
    elif packet_size < 60:  # Very small packets can also be suspicious in some patterns.
        score += 0.12  # Add a smaller penalty for tiny packets.
    if rate > 40:  # Very high packet rate from one source is the strongest local signal here.
        score += 0.35  # Add a large rate-based penalty.
    elif rate > 20:  # Moderately elevated packet rates still contribute to suspicion.
        score += 0.2  # Add a medium rate-based penalty.
    if protocol == 1 and packet_size > 1000:  # Large ICMP packets are treated as another suspicious pattern.
        score += 0.14  # Add a smaller heuristic penalty for that combination.

    score = min(score, 0.95)  # Clamp the score so it never reaches or exceeds 1.0.
    model_version = "live-monitor-v2"  # Default to the heuristic version unless XGBoost participates.
    xgb_probability = None  # Optional second-stage probability for hybrid monitoring.

    if LIVE_XGB_BUNDLE is not None and score >= 0.35:  # Keep heuristic as the fast gate and only invoke XGBoost for suspicious traffic.
        try:
            feature_columns = LIVE_XGB_BUNDLE.get("feature_columns") or list(features.keys())
            feature_df = pd.DataFrame([{col: features.get(col, 0) for col in feature_columns}])
            xgb_probability = float(LIVE_XGB_BUNDLE["model"].predict_proba(feature_df)[0][1])
            score = max(score, xgb_probability)  # Merge heuristic and XGBoost scores conservatively.
            model_version = str(LIVE_XGB_BUNDLE.get("model_version", "live-hybrid-xgb-v1"))
        except Exception:
            xgb_probability = None

    if score >= 0.80:  # Highest score band becomes a review-level event.
        level = "review"  # Review means the signal is strong enough to inspect manually.
    elif score >= 0.50:  # Mid-level anomaly becomes suspicious.
        level = "suspicious"  # Suspicious means notable but not the strongest alert level.
    else:  # Low scores are treated as normal live events.
        level = "normal"  # Normal means the heuristics did not find much concern.

    confidence = int(round((1 - score) * 100)) if level == "normal" else int(round(score * 100))  # Express certainty as a percentage scaled from the score.
    return {  # Return the live-monitor assessment in a compact dictionary.
        "event_level": level,  # Text label for the signal level chosen above.
        "anomaly_score": round(score, 3),  # Rounded numeric score for UI display.
        "confidence": max(1, min(confidence, 99)),  # Clamp confidence to a display-friendly 1..99 range.
        "model_version": model_version,  # Tag the heuristic or hybrid version used to generate the signal.
        "xgb_probability": round(xgb_probability, 3) if xgb_probability is not None else None,  # Include the optional XGBoost probability when available.
    }


def _append_live_event(observed_at, source_ip, destination_ip, protocol, packet_size, assessment):
    LIVE_EVENT_BUFFER.append({  # Push the newest event into the in-memory rolling event buffer.
        "timestamp": observed_at,  # Store when the packet was seen.
        "source_ip": source_ip,  # Store the source IP address.
        "destination_ip": destination_ip,  # Store the destination IP address.
        "protocol": protocol,  # Store the protocol number.
        "packet_size": packet_size,  # Store the total packet length.
        "event_level": assessment["event_level"],  # Copy the inferred severity level.
        "anomaly_score": assessment["anomaly_score"],  # Copy the numeric anomaly score.
        "confidence": assessment["confidence"],  # Copy the derived confidence percentage.
        "model_version": assessment.get("model_version", "live-monitor-v2"),  # Copy the active runtime model version.
        "xgb_probability": assessment.get("xgb_probability"),  # Copy the optional XGBoost probability.
    })


def get_live_monitor_snapshot(seconds=60, limit=5):
    cutoff = now() - timedelta(seconds=seconds)  # Only include events that occurred inside the requested time window.
    with monitor_lock:  # Lock shared state while reading buffers and counters.
        recent = [e for e in LIVE_EVENT_BUFFER if e["timestamp"] >= cutoff]  # Filter buffered events down to the active time window.
        latest = list(reversed(recent))[:limit]  # Show the newest matching events first, capped by limit.
        return {  # Build a dashboard-friendly summary payload.
            "packet_count": LIVE_PACKET_COUNT,  # Include the total number of processed packets.
            "signals_last_window": sum(1 for e in recent if e["event_level"] in ("suspicious", "review")),  # Count only non-normal events in the requested window.
            "latest_events": [  # Format the most recent events for presentation.
                {
                    "time": e["timestamp"].strftime("%H:%M:%S"),  # Present time in a compact clock format.
                    "source_ip": e["source_ip"],  # Include the source IP for each event.
                    "destination_ip": e["destination_ip"],  # Include the destination IP for each event.
                    "event_level": e["event_level"],  # Include the severity label.
                    "confidence": e["confidence"],  # Include the confidence percentage.
                    "anomaly_score": e["anomaly_score"],  # Include the numeric anomaly score.
                    "model_version": e.get("model_version", "live-monitor-v2"),  # Tag the heuristic or hybrid version used to generate the signal.
                    "xgb_probability": e.get("xgb_probability"),  # Include the optional XGBoost probability for hybrid runs.
                    "ti": enrich_ip(e["source_ip"]),  # Attach local threat-intel enrichment for the source IP.
                }
                for e in latest  # Iterate over the newest events chosen above.
            ],
        }


def process_packet(packet):
    global LIVE_PACKET_COUNT  # This function increments the global live packet counter.
    try:  # Packet parsing and database writes can fail, so keep capture resilient.
        if not packet.haslayer(IP):  # Ignore packets that do not contain an IP layer.
            return  # Exit immediately for non-IP traffic.

        observed_at = now()  # Timestamp the packet using Django-aware current time.
        source_ip = packet[IP].src  # Read the source IP from the IP layer.
        destination_ip = packet[IP].dst  # Read the destination IP from the IP layer.
        protocol = packet[IP].proto  # Read the protocol number from the IP header.
        packet_size = len(packet)  # Use the full packet length as a simple traffic feature.
        assessment = _live_monitor_infer(source_ip, protocol, packet_size, observed_at)  # Run the local heuristic model on this packet.

        Threat.objects.create(  # Persist the observed packet as a Threat row for later review.
            source_ip=source_ip,  # Save the source IP.
            destination_ip=destination_ip,  # Save the destination IP.
            protocol=protocol,  # Save the numeric protocol value.
            packet_size=packet_size,  # Save the measured packet size.
            attack_type=f"Live-{assessment['event_level'].title()}",  # Store the live-monitor label as a readable type.
            detected=False,  # This path records live signals, not a final attack verdict.
            timestamp=observed_at  # Save when the packet was observed.
        )

        with monitor_lock:  # Lock shared state before mutating counters and event buffers.
            LIVE_PACKET_COUNT += 1  # Increment the total processed packet count.
            _append_live_event(observed_at, source_ip, destination_ip, protocol, packet_size, assessment)  # Add the event to the live rolling buffer.

    except Exception:  # Swallow packet-level errors so one bad packet does not stop capture.
        pass  # Intentionally ignore errors to keep the monitor running continuously.


def sniff_loop():
    global monitor_running, LAST_MONITOR_ERROR  # This loop reads and updates global monitor state.
    while monitor_running:  # Keep capturing packets until stop_monitor() flips the flag.
        try:  # First try sniffing with an IP filter for efficiency.
            sniff(
                filter="ip",  # Capture only IP packets when the platform supports this filter.
                prn=process_packet,  # Send each captured packet to process_packet().
                store=False,  # Do not keep packets in Scapy memory after processing.
                timeout=2  # Return periodically so the loop can re-check monitor_running.
            )
            LAST_MONITOR_ERROR = ""  # Clear any previous error state after a successful capture cycle.
        except Exception:  # Filtered sniffing can fail on some Windows/Npcap setups.
            # Windows/Npcap setups can fail BPF filter registration.
            # Fallback to unfiltered sniff and rely on process_packet IP checks.
            try:  # Retry without a packet filter as a compatibility fallback.
                sniff(
                    prn=process_packet,  # Continue processing each packet through the same handler.
                    store=False,  # Still avoid storing captured packets in memory.
                    timeout=2  # Still wake periodically to check the run flag.
                )
                LAST_MONITOR_ERROR = ""  # Clear the error if fallback capture works.
            except Exception:  # If unfiltered capture also fails, mark monitoring unavailable.
                LAST_MONITOR_ERROR = "packet_capture_unavailable"  # Save a simple status string for diagnostics or UI.
                time.sleep(1)  # Back off briefly before trying again.


def start_monitor():
    global monitor_thread, monitor_running, LAST_MONITOR_ERROR  # This function initializes global monitor state.

    if monitor_running:  # Avoid starting a second background capture thread.
        return "Already running"  # Report that monitoring was already active.

    LAST_MONITOR_ERROR = ""  # Reset the previous error state before starting again.
    monitor_running = True  # Enable the control flag checked by sniff_loop().
    monitor_thread = threading.Thread(target=sniff_loop)  # Create the background worker thread for packet capture.
    monitor_thread.daemon = True  # Mark the thread as daemon so it does not block process shutdown.
    monitor_thread.start()  # Launch the background sniff loop.

    return "Monitoring started"  # Return a simple status message to the caller.


def stop_monitor():
    global monitor_running  # This function updates the global run flag.

    if not monitor_running:  # If monitoring is already stopped, do nothing else.
        return "Not running"  # Report that there was nothing to stop.

    monitor_running = False  # Signal the sniff loop to exit on its next timeout cycle.
    return "Monitoring stopped"  # Return a simple status message to the caller.
