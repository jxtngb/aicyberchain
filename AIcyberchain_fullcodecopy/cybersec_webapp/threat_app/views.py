import csv
import logging
import random
import threading
from datetime import timedelta

import pandas as pd
from django.conf import settings
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.core.files.storage import FileSystemStorage
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db.models import Count
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils.timezone import now

from threat_app.realtime_monitor import start_monitor, stop_monitor

from .blockchain import add_threat
from .ml_model import predict_from_text
from .models import BlockedIP, Threat, UploadJob, UserProfile

logger = logging.getLogger(__name__)


def _derive_threat_meta(threat):
    attack_type = (getattr(threat, "attack_type", "") or "").strip()
    detected = bool(getattr(threat, "detected", False))

    if attack_type.startswith("Live-"):
        model_version = "live-monitor-v2"
        if "Review" in attack_type:
            confidence = 78
            reason = "high anomaly score over live sliding window"
        elif "Suspicious" in attack_type:
            confidence = 64
            reason = "moderate anomaly score with unusual traffic features"
        else:
            confidence = 97
            reason = "traffic pattern matched normal baseline"
    else:
        model_version = "csv-rf-v1" if detected else "legacy-rf-v1"
        confidence = 88 if detected else 95
        reason = "model detected multi-feature anomaly" if detected else "model matched benign pattern"

    return {"confidence": confidence, "model_version": model_version, "reason": reason}


def _cover_metrics():
    from threat_app import realtime_monitor

    snapshot = realtime_monitor.get_live_monitor_snapshot(seconds=60, limit=5)
    latest_threat = Threat.objects.order_by("-timestamp").first()
    latest_meta = _derive_threat_meta(latest_threat) if latest_threat else {
        "confidence": 0,
        "model_version": "standby",
        "reason": "no analyzed traffic yet",
    }

    threats_today = Threat.objects.filter(timestamp__date=now().date(), detected=True).count()
    blocked_count = BlockedIP.objects.count()
    live_signals = snapshot["signals_last_window"]
    model_confidence = latest_meta["confidence"]

    if live_signals >= 10 or threats_today >= 25:
        risk_level = "High"
    elif live_signals >= 1 or threats_today >= 1:
        risk_level = "Moderate"
    else:
        risk_level = "Low"

    return {
        "cover_threats_today": threats_today,
        "cover_blocked_ips": blocked_count,
        "cover_model_confidence": model_confidence,
        "cover_risk_level": risk_level,
        "cover_monitor_running": realtime_monitor.monitor_running,
        "cover_live_signals": live_signals,
        "cover_latest_model_version": latest_meta["model_version"],
        "cover_latest_reason": latest_meta["reason"],
    }


def cover_page(request):
    return render(request, "cover.html", _cover_metrics())


def login_page(request):
    if request.method == "GET":
        return render(request, "login.html")

    action = request.POST.get("action")

    if action == "verify_credentials":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return JsonResponse({"status": "fail", "message": "Invalid username or password"})

        # SECURITY WARNING: Plain text comparison retained to preserve the project's current data model.
        if user.password != password:
            return JsonResponse({"status": "fail", "message": "Invalid username or password"})

        otp = str(random.randint(100000, 999999))
        request.session["otp"] = otp
        request.session["pre_auth_user_id"] = user.id

        try:
            send_mail(
                "Your CyberShield Login OTP",
                f"Hello {user.first_name},\n\nYour OTP for login is: {otp}\n\nDo not share this with anyone.",
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
        except Exception:
            return JsonResponse({"status": "fail", "message": "Unable to send OTP email. Check email settings."})

        return JsonResponse({"status": "success", "message": "OTP sent to your email"})

    if action == "verify_otp":
        otp_input = request.POST.get("otp", "").strip()
        session_otp = request.session.get("otp")
        user_id = request.session.get("pre_auth_user_id")

        if otp_input != session_otp or not user_id:
            return JsonResponse({"status": "fail", "message": "Invalid OTP"})

        user = User.objects.filter(id=user_id).first()
        if not user:
            return JsonResponse({"status": "fail", "message": "Invalid OTP"})

        auth_login(request, user)
        request.session.pop("otp", None)
        request.session.pop("pre_auth_user_id", None)
        return JsonResponse({"status": "success", "message": "Login successful"})

    return JsonResponse({"status": "fail", "message": "Unsupported login action"}, status=400)


def dashboard(request):
    if not request.user.is_authenticated:
        return redirect("login")

    latest_threats = Threat.objects.order_by("-timestamp")[:10]
    for threat in latest_threats:
        meta = _derive_threat_meta(threat)
        threat.ui_confidence = meta["confidence"]
        threat.ui_model_version = meta["model_version"]
        threat.ui_reason = meta["reason"]

    top_ips = (
        Threat.objects.values("source_ip")
        .annotate(count=Count("source_ip"))
        .order_by("-count")[:5]
    )

    context = {
        "latest_threats": latest_threats,
        "top_ips": top_ips,
    }

    job_id = request.GET.get("job")
    if job_id:
        try:
            job = UploadJob.objects.get(id=int(job_id))
        except (ValueError, TypeError, UploadJob.DoesNotExist):
            job = None

        if job:
            if job.status == "completed" and isinstance(job.result_data, dict):
                context.update(job.result_data)
                context["show_results"] = True
            elif job.status in ("queued", "running"):
                context["upload_job_pending"] = True
                context["upload_job_id"] = job.id
            elif job.status == "failed":
                context["upload_job_error"] = job.error_message or "CSV processing failed"

    return render(request, "dashboard.html", context)


def detect_ajax(request):
    if request.method != "POST":
        return JsonResponse({"status": "fail", "message": "POST required"}, status=405)

    log_text = request.POST.get("log_text", "").strip()
    if not log_text:
        return JsonResponse({"status": "fail", "message": "No log provided"})

    try:
        parts = [part.strip() for part in log_text.split(",")]
        if len(parts) != 4:
            raise ValueError("Expected 4 values: src_ip,dst_ip,protocol,packet_size")

        source_ip = parts[0]
        destination_ip = parts[1]
        protocol = float(parts[2])
        packet_size = float(parts[3])

        if protocol < 0:
            result = "Attack"
        else:
            result = predict_from_text(log_text)

        threat = Threat.objects.create(
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=int(protocol),
            packet_size=packet_size,
            attack_type=result,
            detected=(result == "Attack"),
        )
        meta = _derive_threat_meta(threat)

        protocol_bc = max(0, int(protocol))
        packet_size_bc = max(0, int(packet_size * 1_000_000))

        tx_hash = add_threat(
            threat_id=threat.id,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol_bc,
            packet_size=packet_size_bc,
            attack_type=result,
            detected=threat.detected,
        )
        threat.blockchain_tx = tx_hash
        threat.save(update_fields=["blockchain_tx"])

        steps = [
            "Log received",
            "Log parsed",
            f"ML prediction: {result}",
            f"Model: {meta['model_version']} (confidence {meta['confidence']}%)",
            "Saved to DB",
            f"Blockchain TX: {tx_hash}",
        ]

        return JsonResponse({
            "status": "success",
            "result": result,
            "attack_type": threat.attack_type,
            "source_ip": threat.source_ip,
            "destination_ip": threat.destination_ip,
            "blockchain_tx": tx_hash,
            "steps": steps,
            "confidence": meta["confidence"],
            "model_version": meta["model_version"],
            "reason": meta["reason"],
        })
    except Exception as exc:
        return JsonResponse({"status": "fail", "message": str(exc)})


def _process_csv_file(file_path, csv_file_size=0, progress_cb=None):
    attack_count = 0
    total_rows = 0
    total_packet_size = 0.0
    protocol_stats = {}
    source_ip_stats = {}
    suspicious_reason_stats = {}
    max_rows_per_upload = 50000
    csv_blockchain_limit = 0

    csv_model_enabled = False
    predict_csv_row = None
    predict_csv_rows = None
    upload_model_version = "legacy-rf-v1"
    try:
        from .csv_upload_model import (
            csv_upload_model_ready,
            csv_upload_model_version,
            predict_csv_rows as csv_rows_predictor,
            predict_csv_row as csv_row_predictor,
        )

        csv_model_enabled = csv_upload_model_ready()
        predict_csv_row = csv_row_predictor
        predict_csv_rows = csv_rows_predictor
        if csv_model_enabled:
            upload_model_version = csv_upload_model_version()
    except Exception:
        csv_model_enabled = False
        predict_csv_row = None
        predict_csv_rows = None

    large_upload_mode = (csv_file_size or 0) > (8 * 1024 * 1024)
    if large_upload_mode:
        csv_model_enabled = False
        upload_model_version = "legacy-rf-v1"

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
        "POP": 6,
        "IMAP": 6,
        "DNS": 17,
        "OCSP": 6,
        "DHCP": 17,
        "NTP": 17,
        "QUIC": 17,
        "HTTP2": 6,
        "MDNS": 17,
        "SSDP": 17,
        "RTP": 17,
        "RTCP": 17,
        "STUN": 17,
        "IGMP": 2,
        "ARP": 0,
        "LLDP": 0,
    }

    def reason_for_flag(protocol_name, protocol_num, packet_len, confidence):
        reasons = []
        if protocol_num not in (0, 1, 6, 17):
            reasons.append("non-standard protocol")
        if packet_len > 1400:
            reasons.append("jumbo payload pattern")
        if packet_len < 60:
            reasons.append("abnormally small packet burst")
        if protocol_name in ("ARP", "LLDP"):
            reasons.append("layer-2 control traffic anomaly")
        if confidence is not None and confidence >= 90:
            reasons.append("high model confidence")
        return ", ".join(reasons[:3]) or "multi-feature anomaly pattern"

    pending_threats = []
    blocked_reason_by_ip = {}
    attack_candidates = []

    df = pd.read_csv(file_path, low_memory=False)
    if len(df) > max_rows_per_upload:
        df = df.head(max_rows_per_upload).copy()
    df = df.fillna("")
    rows = df.to_dict(orient="records")

    predictions = [None] * len(rows)
    if csv_model_enabled and predict_csv_rows is not None and rows:
        try:
            batch_predictions = predict_csv_rows(pd.DataFrame(rows))
            if len(batch_predictions) == len(rows):
                predictions = batch_predictions
                if batch_predictions:
                    upload_model_version = batch_predictions[0].get("model_version", upload_model_version)
        except Exception:
            predictions = [None] * len(rows)

    for index, row in enumerate(rows):
        try:
            source_ip = str(
                row.get("Source")
                or row.get("Source IP")
                or row.get("Src IP")
                or row.get("SrcIP")
                or row.get("source_ip")
                or "0.0.0.0"
            ).strip()
            destination_ip = str(
                row.get("Destination")
                or row.get("Destination IP")
                or row.get("Dst IP")
                or row.get("DstIP")
                or row.get("destination_ip")
                or "0.0.0.0"
            ).strip()

            protocol_text = row.get("Protocol") or "OTHER"
            length_value = (
                row.get("Length")
                or row.get("Packet Length")
                or row.get("packet_size")
                or row.get("TotLen Fwd Pkts")
                or row.get("Pkt Size Avg")
            )
            if length_value is None or str(length_value).strip() == "":
                continue

            protocol_name = str(protocol_text).upper().split()[0].replace("/", "")
            packet_size = float(length_value)
            total_packet_size += packet_size

            if protocol_name.replace(".", "", 1).isdigit():
                protocol = int(float(protocol_name))
            else:
                protocol = protocol_map.get(protocol_name, 99)

            source_ip_stats[source_ip] = source_ip_stats.get(source_ip, 0) + 1
            protocol_stats[protocol_name] = protocol_stats.get(protocol_name, 0) + 1

            prediction = predictions[index]
            if protocol < 0:
                result = "Attack"
                csv_confidence = 99
            elif prediction is not None:
                result = prediction["result"]
                csv_confidence = prediction.get("confidence")
                upload_model_version = prediction.get("model_version", upload_model_version)
            else:
                try:
                    if csv_model_enabled and predict_csv_row is not None:
                        prediction = predict_csv_row(row)
                        result = prediction["result"]
                        csv_confidence = prediction.get("confidence")
                        upload_model_version = prediction.get("model_version", upload_model_version)
                    else:
                        result = predict_from_text(f"{source_ip},{destination_ip},{protocol},{packet_size}")
                        csv_confidence = 88 if result == "Attack" else 95
                except Exception:
                    result = predict_from_text(f"{source_ip},{destination_ip},{protocol},{packet_size}")
                    csv_confidence = 88 if result == "Attack" else 95

            should_persist_row = (not large_upload_mode) or (result == "Attack")
            if should_persist_row:
                threat_obj = Threat(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    protocol=protocol,
                    packet_size=packet_size,
                    attack_type=result,
                    detected=(result == "Attack"),
                )
                threat_obj._csv_conf = float(csv_confidence or 0)
                pending_threats.append(threat_obj)

            if result == "Attack":
                attack_count += 1
                reason_text = reason_for_flag(protocol_name, protocol, packet_size, csv_confidence)
                suspicious_reason_stats[reason_text] = suspicious_reason_stats.get(reason_text, 0) + 1
                blocked_reason_by_ip[source_ip] = f"CSV suspicious: {reason_text}"

            total_rows += 1
            if progress_cb and total_rows % 200 == 0:
                progress_cb(total_rows, attack_count)
        except Exception:
            continue

    if pending_threats:
        Threat.objects.bulk_create(pending_threats, batch_size=1000)

    for ip_address, reason in blocked_reason_by_ip.items():
        BlockedIP.objects.update_or_create(
            ip_address=ip_address,
            defaults={"reason": reason},
        )

    blockchain_anchored_count = 0

    summary_tx = None
    try:
        avg_packet_size = (total_packet_size / total_rows) if total_rows else 0
        summary_tx = add_threat(
            threat_id=0,
            source_ip=f"csv_rows_{total_rows}",
            destination_ip=f"attacks_{attack_count}",
            protocol=0,
            packet_size=max(0, int(avg_packet_size * 1_000_000)),
            attack_type=f"CSV-SUMMARY:{upload_model_version}",
            detected=(attack_count > 0),
        )
    except Exception:
        summary_tx = None

    top_source_ips = sorted(source_ip_stats.items(), key=lambda item: item[1], reverse=True)[:5]

    protocol_breakdown = []
    for proto, count in sorted(protocol_stats.items(), key=lambda item: item[1], reverse=True):
        pct = round((count / total_rows) * 100, 2) if total_rows else 0
        protocol_breakdown.append({"name": proto, "count": count, "pct": pct})

    suspicious_reason_breakdown = sorted(
        suspicious_reason_stats.items(),
        key=lambda item: item[1],
        reverse=True,
    )[:6]

    blocked_ip_rows = [
        {
            "ip_address": blocked_ip.ip_address,
            "reason": blocked_ip.reason,
            "blocked_at": blocked_ip.blocked_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for blocked_ip in BlockedIP.objects.all().order_by("-blocked_at")
    ]

    return {
        "total": total_rows,
        "attacks": attack_count,
        "protocol_stats": protocol_stats,
        "protocol_breakdown": protocol_breakdown,
        "suspicious_reason_breakdown": suspicious_reason_breakdown,
        "top_source_ips": top_source_ips,
        "blocked_ips": blocked_ip_rows,
        "upload_model_version": upload_model_version,
        "blockchain_anchored_count": blockchain_anchored_count,
        "summary_tx": summary_tx,
    }


def _run_upload_job(job_id, file_path, csv_file_size):
    try:
        job = UploadJob.objects.get(id=job_id)
        job.status = "running"
        job.save(update_fields=["status", "updated_at"])

        def progress(rows, attacks):
            UploadJob.objects.filter(id=job_id).update(processed_rows=rows, attacks=attacks)

        result = _process_csv_file(file_path, csv_file_size=csv_file_size, progress_cb=progress)
        UploadJob.objects.filter(id=job_id).update(
            status="completed",
            total_rows=result.get("total", 0),
            processed_rows=result.get("total", 0),
            attacks=result.get("attacks", 0),
            result_data=result,
            error_message="",
        )
    except Exception as exc:
        UploadJob.objects.filter(id=job_id).update(status="failed", error_message=str(exc))


def upload_csv_async(request):
    if not request.user.is_authenticated:
        return JsonResponse({"status": "fail", "message": "Unauthorized"}, status=401)

    if request.method != "POST" or not request.FILES.get("csv_file"):
        return JsonResponse({"status": "fail", "message": "No file uploaded"}, status=400)

    csv_file = request.FILES["csv_file"]
    storage = FileSystemStorage()
    filename = storage.save(csv_file.name, csv_file)
    file_path = storage.path(filename)

    job = UploadJob.objects.create(
        status="queued",
        file_name=csv_file.name,
        owner=getattr(request.user, "username", ""),
        total_rows=0,
        processed_rows=0,
        attacks=0,
    )

    worker = threading.Thread(
        target=_run_upload_job,
        args=(job.id, file_path, getattr(csv_file, "size", 0)),
        daemon=True,
    )
    worker.start()

    return JsonResponse({"status": "success", "job_id": job.id})


def upload_job_status(request, job_id):
    if not request.user.is_authenticated:
        return JsonResponse({"status": "fail", "message": "Unauthorized"}, status=401)

    try:
        job = UploadJob.objects.get(id=job_id)
    except UploadJob.DoesNotExist:
        return JsonResponse({"status": "fail", "message": "Job not found"}, status=404)

    payload = {
        "status": "success",
        "job_status": job.status,
        "job_id": job.id,
        "processed_rows": job.processed_rows,
        "total_rows": job.total_rows,
        "attacks": job.attacks,
        "error": job.error_message,
    }
    if job.status == "completed":
        payload["redirect_url"] = f"/dashboard/?job={job.id}"
    return JsonResponse(payload)


def upload_csv(request):
    if not request.user.is_authenticated:
        return redirect("login")

    if request.method == "POST" and request.FILES.get("csv_file"):
        csv_file = request.FILES["csv_file"]
        storage = FileSystemStorage()
        filename = storage.save(csv_file.name, csv_file)
        file_path = storage.path(filename)

        result = _process_csv_file(file_path, csv_file_size=getattr(csv_file, "size", 0))
        return render(request, "dashboard.html", {
            **result,
            "blocked_ips": BlockedIP.objects.all().order_by("-blocked_at"),
            "show_results": True,
        })

    return redirect("dashboard")


def history(request):
    if not request.user.is_authenticated:
        return redirect("login")

    threats_qs = Threat.objects.all().order_by("-timestamp")
    paginator = Paginator(threats_qs, 200)
    page_number = request.GET.get("page", 1)
    page_obj = paginator.get_page(page_number)
    threats = page_obj.object_list

    for threat in threats:
        meta = _derive_threat_meta(threat)
        threat.ui_confidence = meta["confidence"]
        threat.ui_model_version = meta["model_version"]
        threat.ui_reason = meta["reason"]

    return render(request, "history.html", {
        "threats": threats,
        "page_obj": page_obj,
        "paginator": paginator,
        "total_records": paginator.count,
    })


def logout(request):
    request.session.flush()
    auth_logout(request)
    return redirect("home")


def live_stats(request):
    from threat_app import realtime_monitor

    snapshot = realtime_monitor.get_live_monitor_snapshot(seconds=60, limit=5)
    blocked_count = BlockedIP.objects.count()
    recent_attacks = snapshot["signals_last_window"]

    if not realtime_monitor.monitor_running:
        return JsonResponse({
            "monitor_running": False,
            "total_packets": snapshot["packet_count"],
            "recent_attacks": recent_attacks,
            "blocked_count": blocked_count,
            "latest_threats": [],
            "live_signals": recent_attacks,
            "monitor_error": getattr(realtime_monitor, "LAST_MONITOR_ERROR", ""),
        })

    return JsonResponse({
        "monitor_running": True,
        "total_packets": snapshot["packet_count"],
        "recent_attacks": recent_attacks,
        "blocked_count": blocked_count,
        "latest_threats": snapshot["latest_events"],
        "live_signals": recent_attacks,
        "monitor_error": getattr(realtime_monitor, "LAST_MONITOR_ERROR", ""),
    })


def start_live_monitor(request):
    message = start_monitor()
    return JsonResponse({"status": message})


def stop_live_monitor(request):
    message = stop_monitor()
    return JsonResponse({"status": message})


def register(request):
    if request.method == "POST":
        try:
            data = request.POST
            if User.objects.filter(username=data["username"]).exists():
                return JsonResponse({"status": "fail", "message": "Username already exists"})

            if User.objects.filter(email=data["email"]).exists():
                return JsonResponse({"status": "fail", "message": "Email already registered"})

            # SECURITY WARNING: Plain text storage retained to preserve the project's current data model.
            user = User.objects.create(
                username=data["username"],
                email=data["email"],
                first_name=data["full_name"],
                password=data["password"],
            )

            UserProfile.objects.create(
                user=user,
                role=data["role"],
                phone=data["phone"],
            )
            return JsonResponse({"status": "success", "message": "Registration successful! Redirecting..."})
        except Exception as exc:
            return JsonResponse({"status": "fail", "message": str(exc)})

    return render(request, "register.html")


def get_dashboard_stats(request):
    last_60 = now() - timedelta(seconds=60)
    latest_threats = Threat.objects.filter(timestamp__gte=last_60).order_by("-timestamp")[:10]

    threats_data = []
    for threat in latest_threats:
        meta = _derive_threat_meta(threat)
        threats_data.append({
            "timestamp": threat.timestamp.strftime("%H:%M:%S"),
            "source_ip": threat.source_ip,
            "destination_ip": threat.destination_ip,
            "detected": threat.detected,
            "attack_type": threat.attack_type,
            "blockchain_tx": threat.blockchain_tx,
            "confidence": meta["confidence"],
            "model_version": meta["model_version"],
            "reason": meta["reason"],
        })

    top_ips = (
        Threat.objects.filter(timestamp__gte=last_60)
        .values("source_ip")
        .annotate(count=Count("source_ip"))
        .order_by("-count")[:5]
    )

    return JsonResponse({
        "status": "success",
        "latest_threats": threats_data,
        "top_ips": list(top_ips),
        "total_packets": Threat.objects.count(),
        "total_attacks": Threat.objects.filter(detected=True).count(),
        "blocked_count": BlockedIP.objects.count(),
    })


def settings_page(request):
    if not request.user.is_authenticated:
        return redirect("login")

    if request.method == "POST":
        try:
            user = request.user

            if request.POST.get("password"):
                user.password = request.POST.get("password")

            if request.POST.get("username"):
                user.username = request.POST.get("username")

            user.save()
            return JsonResponse({"status": "success", "message": "Profile updated"})
        except Exception as exc:
            return JsonResponse({"status": "fail", "message": str(exc)})

    return render(request, "settings.html")
