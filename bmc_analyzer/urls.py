# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 1. ИМПОРТЫ МАРШРУТИЗАТОРА
# ════════════════════════════════════════════════════════════════════════════

from django.urls import path                              # path() связывает URL-паттерн с обработчиком
from django.http import HttpResponse                      # Базовый класс HTTP-ответа
from django.contrib.auth.views import LoginView, LogoutView  # Встроенные классовые представления Django
from . import views                                       # Обработчики из views.py текущего приложения


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 2. СЛУЖЕБНЫЙ ЭНДПОИНТ ПРОВЕРКИ ДОСТУПНОСТИ
# ════════════════════════════════════════════════════════════════════════════

def health(request):
    return HttpResponse('ok', content_type='text/plain')
    # Liveness probe: не требует аутентификации и не обращается к БД;
    # используется системой мониторинга для проверки живости сервера


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 3. ТАБЛИЦА URL-МАРШРУТОВ ПРИЛОЖЕНИЯ
# ════════════════════════════════════════════════════════════════════════════

urlpatterns = [

    # ── Служебные маршруты ───────────────────────────────────────────────
    path('health/', health, name='health'),

    # ── Главная страница — анализ угроз ──────────────────────────────────
    path('', views.index, name='index'),
    # Пустая строка '' соответствует корневому URL '/'

    # ── Журнал событий безопасности ──────────────────────────────────────
    path('logs/', views.logs_view, name='logs'),

    # ── Оповещения ───────────────────────────────────────────────────────
    path('alerts/', views.alerts_view, name='alerts'),

    path('alerts/dismiss/<int:alert_id>/', views.dismiss_alert, name='dismiss_alert'),
    # <int:alert_id> — конвертер типа: сегмент URL автоматически приводится к int
    # и передаётся как именованный аргумент функции; при нечисловом значении → 404

    path('alerts/dismiss-all/', views.dismiss_all_alerts, name='dismiss_all_alerts'),

    # ── Политики команд и управление ─────────────────────────────────────
    path('policies/', views.policies_view, name='policies'),

    path('policies/simulate/', views.simulate_command_api, name='simulate_command'),
    # AJAX-эндпоинт симулятора: принимает только POST, возвращает JSON;
    # вынесен отдельным URL от /policies/ из-за разного типа ответа

    path('policies/add/', views.add_policy, name='add_policy'),
    # AJAX-эндпоинт создания новой политики; возвращает JSON с данными новой записи

    path('policies/delete/<int:policy_id>/', views.delete_policy, name='delete_policy'),
    # AJAX-эндпоинт удаления; <int:policy_id> защищает от нечисловых идентификаторов

    # ── API статуса безопасности протокола ───────────────────────────────
    path('api/security-status/', views.security_status, name='security_status'),
    # Префикс /api/ — соглашение: машиночитаемый JSON-эндпоинт без HTML-шаблона

    # ── Аутентификация ───────────────────────────────────────────────────
    path('login/', LoginView.as_view(
        template_name='bmc_analyzer/login.html'  # Переопределяет стандартный шаблон Django
    ), name='login'),
    # LoginView.as_view() — метод классового представления, адаптирующий класс
    # к вызову как функцию-обработчик

    path('logout/', LogoutView.as_view(
        next_page='/login/',                         # URL для перенаправления после выхода
        http_method_names=['get', 'post']            # Разрешены оба метода: POST (форма) и GET
    ), name='logout'),
]
