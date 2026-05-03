# BMC_analyzer — Система анализа команд удалённого управления BMC

## Описание проекта
Веб-приложение на Django для анализа угроз внеполосного доступа (УБИ.092).
Версия 2.0.0 — переход с HTTP на HTTPS согласно ГОСТ 12207 (MR-2026-001).

## Архитектура

```
Браузер → HTTPS (TLS 1.3) → Replit Proxy → Django (port 3000)
                                              ├── HttpsRedirectMiddleware
                                              ├── SecurityHeadersMiddleware
                                              ├── bmc_analyzer app
                                              │   ├── views.py (index, docs, security_status)
                                              │   ├── models.py (CommandPolicy)
                                              │   ├── utils.py (calculate_risks, charts)
                                              │   ├── middleware.py (HTTPS + headers)
                                              │   └── tests.py (TS-BMC-01..05)
                                              └── SQLite DB
```

## Стек технологий
- Python 3.10, Django 5.x
- SQLite (dev), Gunicorn (prod)
- Bootstrap 5.3, Matplotlib, Pandas, Sympy
- Docker (python:3.10-slim)

## Ключевые файлы
| Файл | Назначение |
|------|-----------|
| `bmc_analyzer/middleware.py` | HttpsRedirectMiddleware + SecurityHeadersMiddleware |
| `bmc_analyzer/views.py` | Главная, /docs/, /api/security-status/ |
| `bmc_analyzer/tests.py` | Тесты TS-BMC-01..05 (ГОСТ Р 56920, IEEE 829) |
| `django_project/settings.py` | HTTPS-настройки, SECURE_*, HSTS |
| `Dockerfile` | Контейнер v2.0.0 для развёртывания |
| `requirements.txt` | Python-зависимости |

## URL-маршруты
| URL | Описание | Доступ |
|-----|----------|--------|
| `/` | Главная — анализ рисков BMC | Авторизован |
| `/docs/` | Документация по сопровождению (7 заданий) | Авторизован |
| `/api/security-status/` | JSON-статус протокола и заголовков | Авторизован |
| `/login/` | Вход в систему | Публичный |
| `/admin/` | Панель администратора | Суперпользователь |

## Запуск (разработка)
```bash
python manage.py runserver 0.0.0.0:3000
```

## Запуск тестов
```bash
pytest bmc_analyzer/tests.py -v
```

## Переменные окружения
| Переменная | Значение по умолчанию | Описание |
|------------|----------------------|---------|
| `DJANGO_SECRET_KEY` | insecure-dev-key | Секретный ключ (менять в prod) |
| `DEBUG` | True | Режим отладки |
| `REPLIT_DOMAINS` | "" | Домены Replit (авто) |

## Изменения v2.0.0 (MR-2026-001)
- Добавлен HttpsRedirectMiddleware (HTTP→HTTPS редирект 301)
- Добавлен SecurityHeadersMiddleware (HSTS, CSP, X-Frame-Options и др.)
- Обновлены settings.py: SECURE_*, SESSION_COOKIE_SECURE
- Добавлен /docs/ — страница документации по ГОСТ 12207
- Добавлен /api/security-status/ — API проверки безопасности
- Расширены тесты: TS-BMC-01..05 (ГОСТ Р 56920, IEEE 829)
- Создан Dockerfile для контейнерного развёртывания

## Нормативные документы
- ГОСТ 12207 — управление сопровождением ПО
- ГОСТ Р 56920 (ISO/IEC 29119) — тестирование ПО
- IEEE 829 — документация тестирования
- ЕСПД (ГОСТ 19.xxx) — программная документация
