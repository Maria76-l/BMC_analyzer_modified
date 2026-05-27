# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 1. ИМПОРТЫ И ИНИЦИАЛИЗАЦИЯ ЛОГГЕРА
# ════════════════════════════════════════════════════════════════════════════

import logging

logger = logging.getLogger(__name__)
# getLogger(__name__) создаёт логгер с именем модуля (bmc_analyzer.middleware);
# позволяет настраивать уровень логирования этого middleware отдельно от остальных


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 2. MIDDLEWARE ПРИНУДИТЕЛЬНОГО ПЕРЕНАПРАВЛЕНИЯ HTTP → HTTPS
# Перехватывает входящие HTTP-запросы и возвращает 301-редирект на HTTPS.
# Работает через заголовок X-Forwarded-Proto, который подставляет Replit-прокси.
# ════════════════════════════════════════════════════════════════════════════

class HttpsRedirectMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response
        # get_response — следующий обработчик в цепочке middleware или итоговая view-функция;
        # Django передаёт его при инициализации (паттерн «цепочка ответственности»)

    def __call__(self, request):
        # __call__ вызывается Django для каждого входящего HTTP-запроса

        forwarded_proto = request.META.get('HTTP_X_FORWARDED_PROTO', '')
        # request.META — словарь WSGI-переменных окружения;
        # HTTP_X_FORWARDED_PROTO — заголовок от Replit-прокси с исходной схемой клиента

        host = request.META.get('HTTP_HOST', '')
        is_replit_external = 'replit' in host or 'repl.co' in host
        # Проверка домена исключает редирект внутренних служебных запросов
        # (health-check, внутренние proxy-пинги), у которых нет Replit-домена в Host

        if forwarded_proto == 'http' and is_replit_external:
            secure_url = request.build_absolute_uri().replace('http://', 'https://', 1)
            # build_absolute_uri() собирает полный URL с хостом, путём и параметрами;
            # replace(..., 1) — аргумент count=1 заменяет только первое вхождение схемы

            logger.info(
                "HttpsRedirectMiddleware: редирект HTTP→HTTPS для %s",
                request.path,
            )

            from django.http import HttpResponsePermanentRedirect
            return HttpResponsePermanentRedirect(secure_url)
            # 301 Permanent Redirect — браузер кешируют этот редирект;
            # при повторных запросах сразу использует HTTPS без обращения к серверу

        response = self.get_response(request)
        # Если редирект не нужен — передать запрос дальше по цепочке middleware
        return response


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 3. MIDDLEWARE ЗАЩИТНЫХ HTTP-ЗАГОЛОВКОВ
# Добавляет к каждому ответу набор заголовков безопасности:
# HSTS, X-Content-Type-Options, XSS-Protection, CSP и др.
# ════════════════════════════════════════════════════════════════════════════

class SecurityHeadersMiddleware:

    HSTS_MAX_AGE = 31_536_000
    # Константа класса: 1 год в секундах (31 536 000 = 365 × 24 × 3600);
    # используется в заголовке Strict-Transport-Security

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        # Middleware «после ответа»: сначала передаём запрос дальше по цепочке,
        # затем модифицируем уже сформированный объект response

        response['Strict-Transport-Security'] = (
            f'max-age={self.HSTS_MAX_AGE}; includeSubDomains; preload'
        )
        # HSTS — браузер запомнит, что сайт доступен только по HTTPS, на 1 год;
        # includeSubDomains распространяет запрет HTTP на все поддомены;
        # preload позволяет включить домен в встроенный браузерный HSTS-список

        response['X-Content-Type-Options'] = 'nosniff'
        # Запрещает браузеру «угадывать» MIME-тип ответа по содержимому —
        # защита от атак типа MIME sniffing / content type confusion

        response['X-XSS-Protection'] = '1; mode=block'
        # Активирует встроенный XSS-фильтр браузера;
        # mode=block блокирует страницу целиком вместо частичной санации

        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # При переходе на другой домен передаётся только источник (origin),
        # но не полный URL с путём и параметрами — защита от утечки URL

        response['Permissions-Policy'] = (
            'geolocation=(), microphone=(), camera=()'
        )
        # Явно запрещает браузеру предоставлять геолокацию, микрофон и камеру
        # любому скрипту на странице, даже при явном запросе разрешения

        response['Content-Security-Policy'] = (
            "default-src 'self' https:; "
            # Все ресурсы по умолчанию — только с того же домена или по HTTPS

            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            # 'unsafe-inline' разрешает <script>-блоки в шаблонах;
            # cdn.jsdelivr.net — CDN источник Bootstrap JS и Icons

            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            # Разрешает inline-стили и Bootstrap CSS с CDN

            "img-src 'self' data: https:; "
            # data: разрешает Base64-изображения (графики Matplotlib в src="data:...")

            "font-src 'self' https://cdn.jsdelivr.net; "
            # Шрифты Bootstrap Icons загружаются с CDN

            "connect-src 'self' https:; "
            # fetch() и XMLHttpRequest разрешены только к тому же домену или по HTTPS

            "frame-ancestors *;"
            # Разрешает встраивание страницы в iframe с любого домена —
            # необходимо для работы webview-превью в среде Replit
        )
        return response
