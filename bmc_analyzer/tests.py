import json
import pytest
from django.test import TestCase, Client
from django.contrib.auth.models import User
from .models import CommandPolicy
from .utils import calculate_risks, generate_bar_chart



# TS-MOD: Модульное тестирование


@pytest.mark.django_db
class TestModular:
   

    def test_TC_MOD_01_normal_risk_calculation(self):
        
        CommandPolicy.objects.create(command="монтировать ISO", frequency=2, criticality=0.9)
        risks_orig, risks_enh, _, _ = calculate_risks(CommandPolicy.objects.all())
        assert risks_orig[0] == pytest.approx(1.8, 0.01)
        assert risks_enh[0] == pytest.approx(2.16, 0.01)

    def test_TC_MOD_02_zero_criticality(self):
        
        CommandPolicy.objects.create(command="безопасная команда", frequency=5, criticality=0.0)
        risks_orig, risks_enh, _, _ = calculate_risks(CommandPolicy.objects.all())
        assert risks_orig[0] == 0.0
        assert risks_enh[0] == 0.0

    def test_TC_MOD_03_boundary_criticality_one(self):
        
        CommandPolicy.objects.create(command="очень опасная", frequency=3, criticality=1.0)
        risks_orig, risks_enh, _, _ = calculate_risks(CommandPolicy.objects.all())
        assert risks_orig[0] == pytest.approx(3.0, 0.01)
        assert risks_enh[0] == pytest.approx(3.6, 0.01)

    def test_TC_MOD_04_empty_queryset(self):
        
        risks_orig, risks_enh, df_orig, df_enh = calculate_risks(CommandPolicy.objects.none())
        assert risks_orig == []
        assert risks_enh == []
        assert df_orig.empty
        assert df_enh.empty

    def test_TC_MOD_05_bar_chart_base64(self):
        
        img = generate_bar_chart([1.0, 2.0, 3.0], "Тест гистограммы")
        assert isinstance(img, str)
        assert len(img) > 1000
        assert img.startswith('iVBOR'), f"Ожидалось начало 'iVBOR', получено: {img[:10]}"

    def test_low_criticality_no_enhancement(self):
        
        CommandPolicy.objects.create(command="малоопасная", frequency=4, criticality=0.4)
        risks_orig, risks_enh, _, _ = calculate_risks(CommandPolicy.objects.all())
        assert risks_orig[0] == pytest.approx(1.6, 0.01)
        assert risks_enh[0] == pytest.approx(1.6, 0.01)



# TS-FUNC: Функциональное тестирование 

class TestFunctional(TestCase):
    

    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser(
            username='admin', password='admin123', email='admin@test.ru'
        )
        CommandPolicy.objects.create(command="монтировать ISO", frequency=2, criticality=0.9)

    def test_TC_FUNC_01_successful_login(self):
       
        response = self.client.post('/login/', {
            'username': 'admin',
            'password': 'admin123',
        }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Анализ команд')

    def test_TC_FUNC_02_wrong_password(self):
        
        response = self.client.post('/login/', {
            'username': 'admin',
            'password': 'wrong',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Авторизация')

    def test_TC_FUNC_03_logout(self):
        
        self.client.login(username='admin', password='admin123')
        response = self.client.post('/logout/')
        self.assertIn(response.status_code, [301, 302])
        self.assertIn('/login/', response['Location'])

    def test_TC_FUNC_04_risk_index_display(self):
        
        self.client.login(username='admin', password='admin123')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        rows = response.context['table_original_rows']
        self.assertEqual(len(rows), 1)
        self.assertAlmostEqual(rows[0]['risk'], 1.8, places=2)

    def test_TC_FUNC_05_enhanced_index_display(self):
        
        self.client.login(username='admin', password='admin123')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        rows = response.context['table_enhanced_rows']
        self.assertEqual(len(rows), 1)
        self.assertAlmostEqual(rows[0]['risk_enh'], 2.16, places=2)

    def test_TC_FUNC_06_three_tabs_present(self):
        
        self.client.login(username='admin', password='admin123')
        response = self.client.get('/')
        self.assertContains(response, 'Исходный индекс угрозы')
        self.assertContains(response, 'Усиленный индекс угрозы')
        self.assertContains(response, 'Графики сравнения')

    def test_TC_FUNC_07_bar_chart_rendered(self):
        
        self.client.login(username='admin', password='admin123')
        response = self.client.get('/')
        self.assertContains(response, 'data:image/png;base64,')

    def test_TC_FUNC_08_admin_update_command(self):
        
        cmd = CommandPolicy.objects.get(command="монтировать ISO")
        cmd.frequency = 3
        cmd.criticality = 0.95
        cmd.save()
        updated = CommandPolicy.objects.get(command="монтировать ISO")
        self.assertEqual(updated.frequency, 3)
        self.assertAlmostEqual(updated.criticality, 0.95)

    def test_TC_FUNC_09_recalculation_after_update(self):
        
        cmd = CommandPolicy.objects.get(command="монтировать ISO")
        cmd.frequency = 3
        cmd.criticality = 0.95
        cmd.save()
        self.client.login(username='admin', password='admin123')
        response = self.client.get('/')
        rows = response.context['table_original_rows']
        self.assertEqual(len(rows), 1)
        self.assertAlmostEqual(rows[0]['risk'], 2.85, places=2)



# TS-ACC: Приёмочное тестирование 

class TestAcceptance(TestCase):
   

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


# TS-SEC: Тестирование безопасности HTTPS 

class TestHttpsMiddleware(TestCase):
   
    def test_TC_HTTPS_01_http_redirects_to_https(self):
        
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
    

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')

    def test_TC_HTTPS_04_hsts_header(self):
        
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertIn('Strict-Transport-Security', response)
        hsts = response['Strict-Transport-Security']
        self.assertIn('max-age=31536000', hsts)
        self.assertIn('includeSubDomains', hsts)
        self.assertIn('preload', hsts)

    def test_TC_HTTPS_05_x_content_type_options(self):
        
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')

    def test_TC_HTTPS_06_x_frame_options(self):
        
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(response['X-Frame-Options'], 'SAMEORIGIN')

    def test_TC_HTTPS_07_x_xss_protection(self):
        
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(response['X-XSS-Protection'], '1; mode=block')

    def test_TC_HTTPS_08_referrer_policy(self):
        
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(response['Referrer-Policy'], 'strict-origin-when-cross-origin')

    def test_TC_HTTPS_09_content_security_policy(self):
        
        response = self.client.get('/', HTTP_X_FORWARDED_PROTO='https')
        self.assertIn('Content-Security-Policy', response)
        self.assertIn("default-src 'self' https:", response['Content-Security-Policy'])




class TestAccessControl(TestCase):
    

    def test_TC_ACL_01_index_requires_login(self):
        
        response = Client().get('/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])



    def test_TC_ACL_02_api_requires_login(self):
        response = Client().get('/api/security-status/')
        self.assertEqual(response.status_code, 302)

    def test_TC_ACL_03_authorized_index(self):
        user = User.objects.create_user(username='u1', password='p1234567')
        c = Client()
        c.login(username='u1', password='p1234567')
        self.assertEqual(c.get('/').status_code, 200)

   



# TS-API: Интеграционное тестирование API 
class TestSecurityStatusAPI(TestCase):
    

    def setUp(self):
        self.user = User.objects.create_user(username='apiuser', password='apipass123')
        self.client = Client()
        self.client.login(username='apiuser', password='apipass123')

    def test_TC_API_01_returns_json(self):
       
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
        
        response = self.client.get('/api/security-status/', HTTP_X_FORWARDED_PROTO='https')
        data = json.loads(response.content)
        self.assertEqual(data['version'], '2.0.0')

    def test_TC_API_04_hsts_enabled(self):
        
        response = self.client.get('/api/security-status/', HTTP_X_FORWARDED_PROTO='https')
        data = json.loads(response.content)
        self.assertTrue(data['hsts_enabled'])

    def test_TC_API_05_security_headers_list(self):
        response = self.client.get('/api/security-status/', HTTP_X_FORWARDED_PROTO='https')
        data = json.loads(response.content)
        for h in ['Strict-Transport-Security', 'X-Content-Type-Options',
                  'X-Frame-Options', 'Content-Security-Policy']:
            self.assertIn(h, data['security_headers'], f"Отсутствует: {h}")

    def test_TC_API_06_ssl_redirect_field(self):
        """TC-API-06: Ответ содержит поле ssl_redirect=true."""
        response = self.client.get('/api/security-status/', HTTP_X_FORWARDED_PROTO='https')
        data = json.loads(response.content)
        self.assertIn('ssl_redirect', data)
        self.assertTrue(data['ssl_redirect'])

    def test_TC_API_07_hsts_active_field(self):
        """TC-API-07: Ответ содержит поле hsts_active=true."""
        response = self.client.get('/api/security-status/', HTTP_X_FORWARDED_PROTO='https')
        data = json.loads(response.content)
        self.assertIn('hsts_active', data)
        self.assertTrue(data['hsts_active'])

    def test_TC_API_08_secure_cookies_field(self):
        """TC-API-08: Ответ содержит поле secure_cookies."""
        response = self.client.get('/api/security-status/', HTTP_X_FORWARDED_PROTO='https')
        data = json.loads(response.content)
        self.assertIn('secure_cookies', data)
