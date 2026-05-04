
import logging

logger = logging.getLogger(__name__)


class HttpsRedirectMiddleware:
    

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Replit передаёт схему через X-Forwarded-Proto
        forwarded_proto = request.META.get('HTTP_X_FORWARDED_PROTO', '')
        if forwarded_proto == 'http':
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
        response['X-Frame-Options'] = 'SAMEORIGIN'
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
            "frame-ancestors 'self';"
        )
        return response
