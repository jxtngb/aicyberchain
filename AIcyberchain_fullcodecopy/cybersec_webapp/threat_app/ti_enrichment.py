import ipaddress  # Python standard-library module for parsing and classifying IP addresses.
from functools import lru_cache  # Caches repeated lookups so the same IP is not reprocessed each time.


@lru_cache(maxsize=2048)  # Remember up to 2048 previous results for faster repeated enrichment.
def enrich_ip(ip_text):
    try:  # Try to parse the provided text as a valid IPv4 or IPv6 address.
        ip_obj = ipaddress.ip_address((ip_text or "").strip())  # Handle None safely, trim spaces, and convert text into an IP object.
    except Exception:  # If parsing fails, treat the value as an invalid IP input.
        return {  # Return a fallback enrichment record for invalid or missing IP text.
            "network_scope": "unknown",  # Scope cannot be determined because the IP is invalid.
            "reputation": "unknown",  # Reputation is unknown for invalid input.
            "risk_score": 50,  # Use a neutral midpoint risk score for invalid data.
            "risk_flags": ["invalid_ip"],  # Flag the specific reason for the fallback result.
            "asn": "N/A",  # Autonomous System Number is not looked up in this local-only version.
            "country": "N/A",  # Country is also not looked up in this local-only version.
        }

    flags = []  # Collect one or more labels that explain why this risk result was chosen.
    if ip_obj.is_private:  # Check whether the IP belongs to a private internal network range.
        scope = "private"  # Label the network scope as private.
        reputation = "clean"  # Internal/private addresses are treated as clean here.
        risk_score = 5  # Assign a very low risk score to private traffic.
        flags.append("internal")  # Record that the IP is internal.
    elif ip_obj.is_loopback:  # Check whether the IP is a loopback address like 127.0.0.1.
        scope = "loopback"  # Label the network scope as loopback.
        reputation = "clean"  # Loopback addresses are also treated as clean.
        risk_score = 3  # Give loopback addresses an even lower risk score.
        flags.append("loopback")  # Record that the address is loopback traffic.
    elif ip_obj.is_link_local:  # Check whether the IP is in the link-local range.
        scope = "link_local"  # Label the scope as link-local.
        reputation = "clean"  # Link-local addresses are treated as non-malicious by default.
        risk_score = 8  # Assign a low risk score for this local-only address type.
        flags.append("link_local")  # Record the reason for the classification.
    elif ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:  # Catch special-use addresses that are not normal host IPs.
        scope = "special_range"  # Group these unusual cases under a special-range label.
        reputation = "suspicious"  # Mark them as suspicious rather than clean.
        risk_score = 45  # Give a moderate risk score to these special ranges.
        flags.append("special_range")  # Explain the assigned classification.
    else:  # Any remaining valid IP reaches this branch, which effectively means public IP space.
        scope = "public"  # Label the IP as public-facing.
        reputation = "suspicious"  # Public addresses are treated as more risky by this heuristic.
        risk_score = 55  # Assign a slightly above-midpoint risk score.
        flags.append("public_untrusted")  # Record that the IP is public and not inherently trusted.

    return {  # Return the final enrichment record assembled from the branch above.
        "network_scope": scope,  # Final network classification chosen for the IP.
        "reputation": reputation,  # Final reputation label chosen for the IP.
        "risk_score": risk_score,  # Final numeric risk score assigned to the IP.
        "risk_flags": flags,  # Final list of explanation flags describing the decision.
        "asn": "N/A",  # ASN lookup is not implemented in this file.
        "country": "N/A",  # Country lookup is not implemented in this file.
    }
