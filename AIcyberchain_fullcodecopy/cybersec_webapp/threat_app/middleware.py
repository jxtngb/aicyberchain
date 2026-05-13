from django.http import HttpResponseForbidden
from .models import BlockedIP

class ApplicationFirewallMiddleware:
    """
    Level-1 Application Firewall:
    Blocks requests from IPs flagged as malicious.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        if ip and BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden(
                "🚫 Your IP has been blocked due to suspicious activity."
            )

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")
