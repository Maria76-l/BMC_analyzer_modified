"""
Набор тестов для BMC_analyzer v2.0.0

Документы:
  А.В.0001-05-СП — Спецификация процедуры тестирования
  А.В.0001-05-ТС — Спецификация тестов

Соответствие стандартам:
  ГОСТ Р 56920 (ISO/IEC 29119) — классификация тестов
  IEEE 829 — структура тест-документации
  ГОСТ 12207 — этап верификации при сопровождении (§6.4)

Test Suite ID:
  TS-MOD  — модульное тестирование (TC-MOD-01..05)
  TS-FUNC — функциональное тестирование (TC-FUNC-01..09)
  TS-ACC  — приёмочное тестирование (TC-ACC-01..02)
  TS-SEC  — тестирование безопасности HTTPS (TC-HTTPS-01..09, TC-API-01..05)
  TS-ACL  — тестирование контроля доступа (TC-ACL-01..05)
"""

import json
import pytest
from django.test import TestCase, Client
from django.contrib.auth.models import User
from .models import CommandPolicy
from .utils import calculate_risks, generate_bar_chart


# ═════════════════════════════════════════════════════════════════════════════
# TS-MOD: Модульное тестирование (ГОСТ Р 56920 §7.3, А.В.0001-05-ТС Таблица 2)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.django_db
class TestModular:
    """
    Спецификация тестов А.В.0001-05-ТС, Таблица 2 — Модульное тестирование.

    Процедура (А.В.0001-05-СП §2):
      1. Открыть терминал в корне проекта.
      2. Выполнить: pytest -v --tb=short
      3. Зафиксировать результаты в протоколе испытаний.
    Критерий завершения: 100% тестов пройдено.
    """

    def test_TC_MOD_01_normal_risk_calculation(self):
        """
        TC-MOD-01: Расчёт исходного индекса для нормальной команды.
        Предусловие: команда 'монтировать ISO', F=2, C=0.9.
        Ожидаемый результат: risk_original[0]=1.8, risk_enhanced[0]=2.16.
        """
        CommandPolicy.objects.create(command="монтировать ISO", frequency=2, criticality=0.9)
        risks_orig, risks_enh, _, _ = calculate_risks(CommandPolicy.objects.all())
        assert risks_orig[0] == pytest.approx(1.8, 0.01)
        assert risks_enh[0] == pytest.approx(2.16, 0.01)

    def test_TC_MOD_02_zero_criticality(self):
        """
        TC-MOD-02: Граничное значение критичности = 0.
        Ожидаемый результат: risk_original[0]=0.0, risk_enhanced[0]=0.0.
        """
        CommandPolicy.objects.create(command="безопасная команда", frequency=5, criticality=0.0)
        risks_orig, risks_enh, _, _ = calculate_risks(CommandPolicy.objects.all())
        assert risks_orig[0] == 0.0
        assert risks_enh[0] == 0.0

    def test_TC_MOD_03_boundary_criticality_one(self):
        """
        TC-MOD-03: Граничное значение критичности = 1.
        Ожидаемый результат: risk_original[0]=3.0, risk_enhanced[0]=3.6.
        """
        CommandPolicy.objects.create(command="очень опасная", frequency=3, criticality=1.0)
        risks_orig, risks_enh, _, _ = calculate_risks(CommandPolicy.objects.all())
        assert risks_orig[0] == pytest.approx(3.0, 0.01)
        assert risks_enh[0] == pytest.approx(3.6, 0.01)

    def test_TC_MOD_04_empty_queryset(self):
        """
        TC-MOD-04: Пустой список команд.
        Ожидаемый результат: risk_original=[], risk_enhanced=[].
        """
        risks_orig, risks_enh, df_orig, df_enh = calculate_risks(CommandPolicy.objects.none())
        assert risks_orig == []
        assert risks_enh == []
        assert df_orig.empty
        assert df_enh.empty

    def test_TC_MOD_05_bar_chart_base64(self):
        """
        TC-MOD-05: Проверка генерации гистограммы.
        Ожидаемый результат: строка base64 длиной >1000, начинается с 'iVBOR'.
        """
        img = generate_bar_chart([1.0, 2.0, 3.0], "Тест гистограммы")
        assert isinstance(img, str)
        assert len(img) > 1000
        assert img.startswith('iVBOR'), f"Ожидалось начало 'iVBOR', получено: {img[:10]}"

    def test_low_criticality_no_enhancement(self):
        """
        Дополнительный: критичность <= 0.5 — усиление не применяется.
        """
        CommandPolicy.objects.create(command="малоопасная", frequency=4, criticality=0.4)
        risks_orig, risks_enh, _, _ = calculate_risks(CommandPolicy.objects.all())
        assert risks_orig[0] == pytest.approx(1.6, 0.01)
        assert risks_enh[0] == pytest.approx(1.6, 0.01)


# ═════════════════════════════════════════════════════════════════════════════
# TS-FUNC: Функциональное тестирование (ГОСТ Р 56920 §7.3, А.В.0001-05-ТС Таблица 3)
# ═════════════════════════════════════════════════════════════════════════════

class TestFunctional(TestCase):
    """
    Спецификация тестов А.В.0001-05-ТС, Таблица 3 — Функциональное тестирование.

    Процедура (А.В.0001-05-СП §3):
      Проверка аутентификации, расчёта индекса, отображения таблиц и графиков,
      администрирования. Предусловие: сервер запущен, БД содержит начальные данные,
      учётная запись admin создана.
    Критерий завершения: все шаги выполнены, фактические результаты совпадают
      с ожидаемыми. При первом несовпадении тестирование останавливается.
    """

    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser(
            username='admin', password='admin123', email='admin@test.ru'
        )
        CommandPolicy.objects.create(command="монтировать ISO", frequency=2, criticality=0.9)

    def test_TC_FUNC_01_successful_login(self):
        """
        TC-FUNC-01: Успешный вход.
        Действие: перейти на /, ввести admin/admin123, нажать Войти.
        Ожидаемый результат: редирект на /, отображение таблиц. Сессия создана.
        """
        response = self.client.post('/login/', {
            'username': 'admin',
            'password': 'admin123',
        }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Анализ команд')

    def test_TC_FUNC_02_wrong_password(self):
        """
        TC-FUNC-02: Неверный пароль.
        Действие: ввести admin / wrong.
        Ожидаемый результат: сообщение об ошибке, остаться на /login/.
        """
        response = self.client.post('/login/', {
            'username': 'admin',
            'password': 'wrong',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Авторизация')

    def test_TC_FUNC_03_logout(self):
        """
        TC-FUNC-03: Выход из системы.
        Действие: нажать кнопку «Выйти» (POST, Django 5.x).
        Ожидаемый результат: редирект на /login/. Сессия завершена.
        """
        self.client.login(username='admin', password='admin123')
        response = self.client.post('/logout/')
        self.assertIn(response.status_code, [301, 302])
        self.assertIn('/login/', response['Location'])

    def test_TC_FUNC_04_risk_index_display(self):
        """
        TC-FUNC-04: Расчёт индекса для команды 'монтировать ISO' (F=2, C=0.9).
        Ожидаемый результат: risk = 1.8.
        """
        self.client.login(username='admin', password='admin123')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        rows = response.context['table_original_rows']
        self.assertEqual(len(rows), 1)
        self.assertAlmostEqual(rows[0]['risk'], 1.8, places=2)

    def test_TC_FUNC_05_enhanced_index_display(self):
        """
        TC-FUNC-05: Усиленный индекс для 'монтировать ISO' (C=0.9 → ×1.2=1.08, риск=2.16).
        Ожидаемый результат: risk_enh = 2.16.
        """
        self.client.login(username='admin', password='admin123')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        rows = response.context['table_enhanced_rows']
        self.assertEqual(len(rows), 1)
        self.assertAlmostEqual(rows[0]['risk_enh'], 2.16, places=2)

    def test_TC_FUNC_06_three_tabs_present(self):
        """
        TC-FUNC-06: Наличие вкладок.
        Ожидаемый результат: три вкладки — «Исходный», «Усиленный», «Графики».
        """
        self.client.login(username='admin', password='admin123')
        response = self.client.get('/')
        self.assertContains(response, 'Исходный индекс угрозы')
        self.assertContains(response, 'Усиленный индекс угрозы')
        self.assertContains(response, 'Графики сравнения')

    def test_TC_FUNC_07_bar_chart_rendered(self):
        """
        TC-FUNC-07: Цветовая индикация — гистограмма присутствует на странице.
        Ожидаемый результат: base64-строка PNG (data:image/png;base64,).
        """
        self.client.login(username='admin', password='admin123')
        response = self.client.get('/')
        self.assertContains(response, 'data:image/png;base64,')

    def test_TC_FUNC_08_admin_update_command(self):
        """
        TC-FUNC-08: Изменение параметров через API (эмуляция адм. сохранения).
        Действие: обновить F=3, C=0.95 для «монтировать ISO».
        Ожидаемый результат: объект обновлён в БД без ошибок.
        """
        cmd = CommandPolicy.objects.get(command="монтировать ISO")
        cmd.frequency = 3
        cmd.criticality = 0.95
        cmd.save()
        updated = CommandPolicy.objects.get(command="монтировать ISO")
        self.assertEqual(updated.frequency, 3)
        self.assertAlmostEqual(updated.criticality, 0.95)

    def test_TC_FUNC_09_recalculation_after_update(self):
        """
        TC-FUNC-09: Пересчёт индекса после изменения (F=3, C=0.95 → R=2.85).
        Ожидаемый результат: индекс = 2.85.
        """
        cmd = CommandPolicy.objects.get(command="монтировать ISO")
        cmd.frequency = 3
        cmd.criticality = 0.95
        cmd.save()
        self.client.login(username='admin', password='admin123')
        response = self.client.get('/')
        rows = response.context['table_original_rows']
        self.assertEqual(len(rows), 1)
        self.assertAlmostEqual(rows[0]['risk'], 2.85, places=2)


# ═════════════════════════════════════════════════════════════════════════════
# TS-ACC: Приёмочное тестирование (ГОСТ Р 56920 §7.6, А.В.0001-05-ТС Таблица 4)
# ═════════════════════════════════════════════════════════════════════════════

class TestAcceptance(TestCase):
    """
    Спецификация тестов А.В.0001-05-ТС, Таблица 4 — Приёмочное тестирование.
    Высокоуровневые тесты соответствия Техническому заданию.
    """

    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser(
            username='admin', password='admin123', email='admin@test.ru'
        )
        for cmd, freq, crit in [
            ("монтировать ISO", 2, 0.9),
            ("включить power", 1, 0.3),
            ("сброс пароля IPMI", 3, 0.8),
        ]:
            CommandPolicy.objects.create(command=cmd, frequency=freq, criticality=crit)

    def test_TC_ACC_01_full_admin_cycle(self):
        """
        TC-ACC-01: Полный цикл работы администратора.
        Действие: войти как admin, просмотреть таблицы, изменить параметры, выйти.
        Ожидаемый результат: все функции доступны, изменения сохраняются.
        """
        login_resp = self.client.post('/login/', {
            'username': 'admin', 'password': 'admin123'
        }, follow=True)
        self.assertEqual(login_resp.status_code, 200)

        index_resp = self.client.get('/')
        self.assertEqual(index_resp.status_code, 200)
        self.assertContains(index_resp, 'монтировать ISO')

        cmd = CommandPolicy.objects.get(command="монтировать ISO")
        cmd.frequency = 3
        cmd.criticality = 0.95
        cmd.save()

        updated_resp = self.client.get('/')
        self.assertEqual(updated_resp.status_code, 200)
        rows = updated_resp.context['table_original_rows']
        self.assertAlmostEqual(rows[0]['risk'], 2.85, places=2)

        logout_resp = self.client.post('/logout/')
        self.assertIn(logout_resp.status_code, [301, 302])
        self.assertIn('/login/', logout_resp['Location'])

    def test_TC_ACC_02_all_tests_compliance(self):
        """
        TC-ACC-02: Проверка соответствия Техническому заданию.
        Условие: система отображает данные, выполняет расчёты, обеспечивает
        аутентификацию согласно ТЗ. Дефектов нет.
        """
        self.client.login(username='admin', password='admin123')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

        ctx = response.context
        self.assertIn('table_original_rows', ctx)
        self.assertIn('table_enhanced_rows', ctx)
        self.assertIn('bar_chart', ctx)
        self.assertIn('pie_chart', ctx)
        self.assertIn('line_chart', ctx)

        self.assertGreater(len(ctx['table_original_rows']), 0)
        for row in ctx['table_original_rows']:
            self.assertGreaterEqual(row['risk'], 0)


# ═════════════════════════════════════════════════════════════════════════════
# TS-SEC: Тестирование безопасности HTTPS (MR-2026-001, ГОСТ Р 56920 §7.4)
# ═════════════════════════════════════════════════════════════════════════════

class TestHttpsMiddleware(TestCase):
    """
    Тестирование HttpsRedirectMiddleware (переход HTTP→HTTPS).
    Тест-кейсы TC-HTTPS-01..03.
    """

    def test_TC_HTTPS_01_http_redirects_to_https(self):
        """
        TC-HTTPS-01: HTTP-запрос → 301 Redirect, Location начинается с https://.
        Предусловие: заголовок X-Forwarded-Proto: http.
        """
        client = Client()
        response = client.get(
            '/login/',
            HTTP_X_FORWARDED_PROTO='http',
            HTTP_HOST='testserver',
        )
        self.assertEqual(response.status_code, 301)
        self.assertTrue(
            response['Location'].startswith('https://'),
            f"Ожидался https://, получен: {response.get('Location', '')}"
        )

    def test_TC_HTTPS_02_https_not_redirected(self):
        """
        TC-HTTPS-02: HTTPS-запрос не вызывает повторного редиректа.
        """
        client = Client()
        response = client.get('/login/', HTTP_X_FORWARDED_PROTO='https')
        self.assertNotEqual(response.status_code, 301)

    def test_TC_HTTPS_03_no_forwarded_proto_no_redirect(self):
        """
        TC-HTTPS-03: Без X-Forwarded-Proto редирект не выполняется.
        """
        client = Client()
        response = client.get('/login/')
        self.assertNotEqual(response.status_code, 301)


class TestSecurityHeaders(TestCase):
    """
    Тестирование SecurityHeadersMiddleware.
    Тест-кейсы TC-HTTPS-04..09.
    """

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')

    def test_TC_HTTPS_04_hsts_header(self):
        """
        TC-HTTPS-04: Заголовок Strict-Transport-Security с max-age=31536000.
        """
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertIn('Strict-Transport-Security', response)
        hsts = response['Strict-Transport-Security']
        self.assertIn('max-age=31536000', hsts)
        self.assertIn('includeSubDomains', hsts)
        self.assertIn('preload', hsts)

    def test_TC_HTTPS_05_x_content_type_options(self):
        """
        TC-HTTPS-05: Заголовок X-Content-Type-Options: nosniff.
        """
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')

    def test_TC_HTTPS_06_x_frame_options(self):
        """
        TC-HTTPS-06: Заголовок X-Frame-Options: SAMEORIGIN.
        """
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(response['X-Frame-Options'], 'SAMEORIGIN')

    def test_TC_HTTPS_07_x_xss_protection(self):
        """
        TC-HTTPS-07: Заголовок X-XSS-Protection: 1; mode=block.
        """
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(response['X-XSS-Protection'], '1; mode=block')

    def test_TC_HTTPS_08_referrer_policy(self):
        """
        TC-HTTPS-08: Заголовок Referrer-Policy: strict-origin-when-cross-origin.
        """
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(response['Referrer-Policy'], 'strict-origin-when-cross-origin')

    def test_TC_HTTPS_09_content_security_policy(self):
        """
        TC-HTTPS-09: Заголовок Content-Security-Policy содержит default-src.
        """
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertIn('Content-Security-Policy', response)
        self.assertIn("default-src 'self' https:", response['Content-Security-Policy'])


# ═════════════════════════════════════════════════════════════════════════════
# TS-ACL: Контроль доступа (TC-ACL-01..05)
# ═════════════════════════════════════════════════════════════════════════════

class TestAccessControl(TestCase):
    """Тестирование контроля доступа к защищённым страницам."""

    def test_TC_ACL_01_index_requires_login(self):
        """TC-ACL-01: / без авторизации → редирект на /login/."""
        response = Client().get('/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])

    def test_TC_ACL_02_docs_requires_login(self):
        """TC-ACL-02: /docs/ без авторизации → редирект на /login/."""
        response = Client().get('/docs/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])

    def test_TC_ACL_03_api_requires_login(self):
        """TC-ACL-03: /api/security-status/ без авторизации → редирект."""
        response = Client().get('/api/security-status/')
        self.assertEqual(response.status_code, 302)

    def test_TC_ACL_04_authorized_index(self):
        """TC-ACL-04: Авторизованный пользователь получает доступ к /."""
        user = User.objects.create_user(username='u1', password='p1234567')
        c = Client()
        c.login(username='u1', password='p1234567')
        self.assertEqual(c.get('/').status_code, 200)

    def test_TC_ACL_05_authorized_docs(self):
        """TC-ACL-05: Авторизованный пользователь получает доступ к /docs/."""
        user = User.objects.create_user(username='u2', password='p1234567')
        c = Client()
        c.login(username='u2', password='p1234567')
        self.assertEqual(c.get('/docs/').status_code, 200)


# ═════════════════════════════════════════════════════════════════════════════
# TS-API: Интеграционное тестирование API (TC-API-01..05)
# ═════════════════════════════════════════════════════════════════════════════

class TestSecurityStatusAPI(TestCase):
    """Интеграционное тестирование /api/security-status/."""

    def setUp(self):
        self.user = User.objects.create_user(username='apiuser', password='apipass123')
        self.client = Client()
        self.client.login(username='apiuser', password='apipass123')

    def test_TC_API_01_returns_json(self):
        """TC-API-01: API возвращает корректный JSON со статусом 200."""
        response = self.client.get('/api/security-status/', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('protocol', data)
        self.assertIn('is_secure', data)
        self.assertIn('version', data)

    def test_TC_API_02_https_protocol(self):
        """TC-API-02: При X-Forwarded-Proto: https → protocol=HTTPS, is_secure=true."""
        response = self.client.get('/api/security-status/', HTTP_X_FORWARDED_PROTO='https')
        data = json.loads(response.content)
        self.assertEqual(data['protocol'], 'HTTPS')
        self.assertTrue(data['is_secure'])

    def test_TC_API_03_version(self):
        """TC-API-03: Версия API = 2.0.0."""
        response = self.client.get('/api/security-status/', HTTP_X_FORWARDED_PROTO='https')
        data = json.loads(response.content)
        self.assertEqual(data['version'], '2.0.0')

    def test_TC_API_04_hsts_enabled(self):
        """TC-API-04: Поле hsts_enabled=true."""
        response = self.client.get('/api/security-status/', HTTP_X_FORWARDED_PROTO='https')
        data = json.loads(response.content)
        self.assertTrue(data['hsts_enabled'])

    def test_TC_API_05_security_headers_list(self):
        """TC-API-05: Список security_headers содержит все обязательные заголовки."""
        response = self.client.get('/api/security-status/', HTTP_X_FORWARDED_PROTO='https')
        data = json.loads(response.content)
        for h in ['Strict-Transport-Security', 'X-Content-Type-Options',
                  'X-Frame-Options', 'Content-Security-Policy']:
            self.assertIn(h, data['security_headers'], f"Отсутствует: {h}")
