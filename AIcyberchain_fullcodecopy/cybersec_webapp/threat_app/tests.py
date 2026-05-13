from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from .models import BlockedIP, Threat
from .views import _process_csv_file


class ThreatAppViewTests(TestCase):
    @patch("threat_app.views.add_threat", return_value="0xtesthash")
    @patch("threat_app.views.predict_from_text", return_value="Attack")
    def test_detect_ajax_returns_fields_used_by_dashboard(self, mock_predict, mock_add_threat):
        response = self.client.post(reverse("detect_ajax"), {
            "log_text": "10.0.0.1,10.0.0.2,6,512",
        })

        self.assertEqual(response.status_code, 200)
        payload = response.json()

        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["attack_type"], "Attack")
        self.assertEqual(payload["source_ip"], "10.0.0.1")
        self.assertEqual(payload["destination_ip"], "10.0.0.2")
        self.assertEqual(payload["blockchain_tx"], "0xtesthash")
        self.assertIn("confidence", payload)
        self.assertEqual(Threat.objects.count(), 1)

    def test_live_stats_uses_real_signal_count(self):
        BlockedIP.objects.create(ip_address="10.0.0.10", reason="existing block")

        with patch("threat_app.realtime_monitor.get_live_monitor_snapshot", return_value={
            "packet_count": 12,
            "signals_last_window": 4,
            "latest_events": [{"source_ip": "10.0.0.3"}],
        }), patch("threat_app.realtime_monitor.monitor_running", True), patch(
            "threat_app.realtime_monitor.LAST_MONITOR_ERROR",
            "",
        ):
            response = self.client.get(reverse("live_stats"))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["recent_attacks"], 4)
        self.assertEqual(payload["live_signals"], 4)
        self.assertEqual(payload["blocked_count"], 1)

    @patch("threat_app.views.add_threat", return_value="0xcsvhash")
    @patch("threat_app.views.predict_from_text", return_value="Attack")
    def test_csv_processing_preserves_existing_blocked_ips(self, mock_predict, mock_add_threat):
        BlockedIP.objects.create(ip_address="10.0.0.10", reason="manual block")

        with NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as handle:
            handle.write("Source,Destination,Protocol,Length\n")
            handle.write("10.0.0.11,10.0.0.12,TCP,1500\n")
            csv_path = handle.name

        try:
            result = _process_csv_file(csv_path)
        finally:
            Path(csv_path).unlink(missing_ok=True)

        self.assertEqual(result["attacks"], 1)
        self.assertTrue(BlockedIP.objects.filter(ip_address="10.0.0.10").exists())
        self.assertTrue(BlockedIP.objects.filter(ip_address="10.0.0.11").exists())

    def test_cover_page_uses_real_metrics_context(self):
        Threat.objects.create(
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            protocol=6,
            packet_size=128.0,
            attack_type="Attack",
            detected=True,
        )
        BlockedIP.objects.create(ip_address="10.0.0.9", reason="test block")

        response = self.client.get(reverse("home"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Blocked IPs")
        self.assertEqual(response.context["cover_threats_today"], 1)
        self.assertEqual(response.context["cover_blocked_ips"], 1)
