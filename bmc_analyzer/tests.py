"""
Набор тестов для BMC_analyzer v2.0.0

Соответствие:
  - ГОСТ Р 56920 (ISO/IEC 29119) — классификация тестов
  - IEEE 829 — структура тест-документации
  - ГОСТ 12207 — этап верификации при сопровождении (§6.4)

Test Suite ID: TS-BMC-01..TS-BMC-05
"""

import json
import pytest
from django.test import TestCase, Client
from django.contrib.auth.models import User
from .models import CommandPolicy
from .utils import calculate_risks


# ─────────────────────────────────────────────────────────────────────────────
# TS-BMC-01: Функциональное тестирование бизнес-логики (ГОСТ Р 56920 §7.3)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
class TestCalculateRisks:
    """
    IEEE 829 Test Case Specification — TS-BMC-01
    Проверка расчёта индекса угрозы R = C × F
    """

    def test_normal_case(self):
        """TC-BMC-01-01: Проверка расчёта для команды с F=2, C=0.9"""
        CommandPolicy.objects.create(command="монтировать ISO", frequency=2, criticality=0.9)
        risks_orig, risks_enh, _, _ = calculate_risks(CommandPolicy.objects.all())
        assert risks_orig[0] == pytest.approx(1.8, 0.01)
        assert risks_enh[0] == pytest.approx(2.16, 0.01)

    def test_zero_criticality(self):
        """TC-BMC-01-02: Критичность=0 -> риск=0, усиленный риск=0"""
        CommandPolicy.objects.create(command="безопасная команда", frequency=5, criticality=0.0)
        risks_orig, risks_enh, _, _ = calculate_risks(CommandPolicy.objects.all())
        assert risks_orig[0] == 0.0
        assert risks_enh[0] == 0.0

    def test_boundary_criticality_one(self):
        """TC-BMC-01-03: Критичность=1 -> риск=F, усиленный=F*1.2"""
        CommandPolicy.objects.create(command="очень опасная", frequency=3, criticality=1.0)
        risks_orig, risks_enh, _, _ = calculate_risks(CommandPolicy.objects.all())
        assert risks_orig[0] == pytest.approx(3.0, 0.01)
        assert risks_enh[0] == pytest.approx(3.6, 0.01)

    def test_empty_queryset(self):
        """TC-BMC-01-04: Пустой набор команд -> пустые списки"""
        risks_orig, risks_enh, df_orig, df_enh = calculate_risks(CommandPolicy.objects.none())
        assert risks_orig == []
        assert risks_enh == []
        assert df_orig.empty
        assert df_enh.empty

    def test_low_criticality_no_enhancement(self):
        """TC-BMC-01-05: Критичность <= 0.5 — усиления нет"""
        CommandPolicy.objects.create(command="малоопасная", frequency=4, criticality=0.4)
        risks_orig, risks_enh, _, _ = calculate_risks(CommandPolicy.objects.all())
        assert risks_orig[0] == pytest.approx(1.6, 0.01)
        assert risks_enh[0] == pytest.approx(1.6, 0.01)


# ─────────────────────────────────────────────────────────────────────────────
# TS-BMC-02: Тестирование HTTPS-перехода (ГОСТ Р 56920 §7.4 — безопасность)
# ─────────────────────────────────────────────────────────────────────────────

class TestHttpsMiddleware(TestCase):
    """
    IEEE 829 Test Case Specification — TS-BMC-02
    Проверка HttpsRedirectMiddleware (MR-2026-001)
    """

    def test_http_redirects_to_https(self):
        """TC-HTTPS-01: HTTP-запрос должен вернуть 301 с Location https://"""
        client = Client()
        response = client.get(
            '/login/',
            HTTP_X_FORWARDED_PROTO='http',
            HTTP_HOST='testserver',
        )
        self.assertEqual(response.status_code, 301)
        self.assertTrue(
            response['Location'].startswith('https://'),
            f"Ожидался Location с https://, получен: {response.get('Location', '')}"
        )

    def test_https_request_not_redirected(self):
        """TC-HTTPS-02: HTTPS-запрос не должен вызывать повторный редирект"""
        client = Client()
        response = client.get(
            '/login/',
            HTTP_X_FORWARDED_PROTO='https',
        )
        self.assertNotEqual(response.status_code, 301)

    def test_no_forwarded_proto_no_redirect(self):
        """TC-HTTPS-03: Без заголовка X-Forwarded-Proto редирект не выполняется"""
        client = Client()
        response = client.get('/login/')
        self.assertNotEqual(response.status_code, 301)


# ─────────────────────────────────────────────────────────────────────────────
# TS-BMC-03: Тестирование заголовков безопасности (ГОСТ Р 56920 §7.4)
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityHeaders(TestCase):
    """
    IEEE 829 Test Case Specification — TS-BMC-03
    Проверка SecurityHeadersMiddleware
    """

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')

    def test_hsts_header_present(self):
        """TC-HTTPS-04: Заголовок Strict-Transport-Security присутствует"""
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertIn('Strict-Transport-Security', response)
        hsts = response['Strict-Transport-Security']
        self.assertIn('max-age=31536000', hsts)
        self.assertIn('includeSubDomains', hsts)
        self.assertIn('preload', hsts)

    def test_x_content_type_options(self):
        """TC-HTTPS-05: Заголовок X-Content-Type-Options: nosniff"""
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertIn('X-Content-Type-Options', response)
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')

    def test_x_frame_options(self):
        """TC-HTTPS-06: Заголовок X-Frame-Options: SAMEORIGIN"""
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertIn('X-Frame-Options', response)
        self.assertEqual(response['X-Frame-Options'], 'SAMEORIGIN')

    def test_x_xss_protection(self):
        """TC-HTTPS-07: Заголовок X-XSS-Protection: 1; mode=block"""
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertIn('X-XSS-Protection', response)
        self.assertEqual(response['X-XSS-Protection'], '1; mode=block')

    def test_referrer_policy(self):
        """TC-HTTPS-08: Заголовок Referrer-Policy"""
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertIn('Referrer-Policy', response)
        self.assertEqual(response['Referrer-Policy'], 'strict-origin-when-cross-origin')

    def test_content_security_policy(self):
        """TC-HTTPS-09: Заголовок Content-Security-Policy присутствует"""
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertIn('Content-Security-Policy', response)
        csp = response['Content-Security-Policy']
        self.assertIn("default-src 'self' https:", csp)


# ─────────────────────────────────────────────────────────────────────────────
# TS-BMC-04: Контроль доступа (авторизация) (ГОСТ Р 56920 §7.3)
# ─────────────────────────────────────────────────────────────────────────────

class TestAccessControl(TestCase):
    """
    IEEE 829 Test Case Specification — TS-BMC-04
    Проверка контроля доступа к защищённым страницам
    """

    def test_index_requires_login(self):
        """TC-ACL-01: Главная страница без авторизации → редирект на /login/"""
        client = Client()
        response = client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])

    def test_docs_requires_login(self):
        """TC-ACL-02: /docs/ без авторизации → редирект на /login/"""
        client = Client()
        response = client.get('/docs/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])

    def test_security_status_requires_login(self):
        """TC-ACL-03: /api/security-status/ без авторизации → редирект"""
        client = Client()
        response = client.get('/api/security-status/')
        self.assertEqual(response.status_code, 302)

    def test_authorized_access_index(self):
        """TC-ACL-04: Авторизованный пользователь получает доступ к главной"""
        user = User.objects.create_user(username='authuser', password='pass1234')
        client = Client()
        client.login(username='authuser', password='pass1234')
        response = client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_authorized_access_docs(self):
        """TC-ACL-05: Авторизованный пользователь получает доступ к /docs/"""
        user = User.objects.create_user(username='docsuser', password='pass1234')
        client = Client()
        client.login(username='docsuser', password='pass1234')
        response = client.get('/docs/')
        self.assertEqual(response.status_code, 200)


# ─────────────────────────────────────────────────────────────────────────────
# TS-BMC-05: Интеграционное тестирование API (ГОСТ Р 56920 §7.5)
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityStatusAPI(TestCase):
    """
    IEEE 829 Test Case Specification — TS-BMC-05
    Проверка API-эндпоинта /api/security-status/
    """

    def setUp(self):
        self.user = User.objects.create_user(username='apiuser', password='apipass123')
        self.client = Client()
        self.client.login(username='apiuser', password='apipass123')

    def test_api_returns_json(self):
        """TC-API-01: API возвращает корректный JSON"""
        response = self.client.get(
            '/api/security-status/',
            HTTP_X_FORWARDED_PROTO='https',
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('protocol', data)
        self.assertIn('is_secure', data)
        self.assertIn('version', data)

    def test_api_https_protocol(self):
        """TC-API-02: При X-Forwarded-Proto: https → protocol=HTTPS, is_secure=true"""
        response = self.client.get(
            '/api/security-status/',
            HTTP_X_FORWARDED_PROTO='https',
        )
        data = json.loads(response.content)
        self.assertEqual(data['protocol'], 'HTTPS')
        self.assertTrue(data['is_secure'])

    def test_api_version(self):
        """TC-API-03: Версия API соответствует v2.0.0"""
        response = self.client.get(
            '/api/security-status/',
            HTTP_X_FORWARDED_PROTO='https',
        )
        data = json.loads(response.content)
        self.assertEqual(data['version'], '2.0.0')

    def test_api_hsts_enabled(self):
        """TC-API-04: Поле hsts_enabled=true"""
        response = self.client.get(
            '/api/security-status/',
            HTTP_X_FORWARDED_PROTO='https',
        )
        data = json.loads(response.content)
        self.assertTrue(data['hsts_enabled'])

    def test_api_security_headers_list(self):
        """TC-API-05: Список security_headers содержит все обязательные заголовки"""
        response = self.client.get(
            '/api/security-status/',
            HTTP_X_FORWARDED_PROTO='https',
        )
        data = json.loads(response.content)
        required = [
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Content-Security-Policy',
        ]
        for header in required:
            self.assertIn(header, data['security_headers'], f"Отсутствует заголовок: {header}")
