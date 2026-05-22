
import logging

logger = logging.getLogger(__name__)


class HttpsRedirectMiddleware:
    

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Replit passes the original scheme via X-Forwarded-Proto.
        # Only redirect when the header is explicitly "http" AND a host header
        # from an external Replit domain is present — this avoids redirecting
        # internal health-check / proxy traffic that arrives without the header.
        forwarded_proto = request.META.get('HTTP_X_FORWARDED_PROTO', '')
        host = request.META.get('HTTP_HOST', '')
        is_replit_external = 'replit' in host or 'repl.co' in host
        if forwarded_proto == 'http' and is_replit_external:
            secure_url = request.build_absolute_uri().replace('http://', 'https://', 1)
            logger.info(
                "HttpsRedirectMiddleware: редирект HTTP→HTTPS для %s",
                request.path,
            )
            from django.http import HttpResponsePermanentRedirect
            return HttpResponsePermanentRedirect(secure_url)

        response = self.get_response(request)
        return response


class SecurityHeadersMiddleware:
    

    HSTS_MAX_AGE = 31_536_000  # 1 год (согласно статистике вендоров)

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        response['Strict-Transport-Security'] = (
            f'max-age={self.HSTS_MAX_AGE}; includeSubDomains; preload'
        )
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = (
            'geolocation=(), microphone=(), camera=()'
        )
        response['Content-Security-Policy'] = (
            "default-src 'self' https:; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self' https:; "
            "frame-ancestors *;"
        )
        return response
