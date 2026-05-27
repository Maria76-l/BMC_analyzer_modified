# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 1. ИМПОРТЫ
# ════════════════════════════════════════════════════════════════════════════

from django.shortcuts import render, get_object_or_404, redirect
# render()            — компилирует шаблон с контекстом и возвращает HttpResponse
# get_object_or_404() — выполняет objects.get(); при DoesNotExist отвечает кодом 404
# redirect()          — возвращает HttpResponseRedirect (302) на именованный URL

from django.contrib.auth.decorators import login_required
# Декоратор: если пользователь не аутентифицирован — перенаправляет на LOGIN_URL (/login/)

from django.http import JsonResponse
# Подкласс HttpResponse с автоматической сериализацией словаря в JSON
# и установкой Content-Type: application/json

from django.utils import timezone
# Обёртка над datetime с учётом TIME_ZONE из settings; timezone.now() → aware datetime

from django.contrib import messages
# Фреймворк одноразовых сообщений: сохраняются в сессии, отображаются в следующем запросе

from django.core.paginator import Paginator
# Разбивает QuerySet на страницы через LIMIT/OFFSET без загрузки всех записей в память

from django.conf import settings as django_settings
# Объект настроек проекта; используется для чтения SECURE_HSTS_SECONDS и др.

from .models import CommandPolicy, EventLog, IntegrityRecord, Alert
from .utils import (
    calculate_risks, generate_bar_chart, generate_pie_chart, generate_line_chart,
    log_event, check_command_policy, run_integrity_check, create_alert, get_client_ip
)


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 2. ОБЩИЙ КОНТЕКСТ ШАБЛОНОВ
# Формирует словарь, добавляемый к контексту каждой страницы
# ════════════════════════════════════════════════════════════════════════════

def _base_ctx(request):
    unread_alerts = Alert.objects.filter(dismissed_at__isnull=True).count()
    # __isnull=True — lookup Django ORM, аналог SQL WHERE dismissed_at IS NULL;
    # count() выполняет COUNT(*) без загрузки объектов в память

    return {
        'is_admin':      request.user.is_staff,
        # is_staff — признак принадлежности к персоналу (доступ к /admin/)
        'unread_alerts': unread_alerts,
        # Счётчик для красного бейджа в навигационной панели
    }


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 3. ГЛАВНАЯ СТРАНИЦА — АНАЛИЗ УГРОЗ
# Рассчитывает индекс угрозы R = C × F для каждой команды,
# формирует таблицы и три графика для дашборда
# ════════════════════════════════════════════════════════════════════════════

@login_required
def index(request):
    commands = CommandPolicy.objects.all().order_by('id')
    # all() возвращает «ленивый» QuerySet — SQL выполняется при первом обращении к данным

    risk_orig, risk_enh, df_orig, df_enh = calculate_risks(commands)
    # Распаковка кортежа из 4 элементов: два списка индексов угрозы и два DataFrame

    table_original_rows = []
    for i, cmd in enumerate(commands):
        # enumerate() возвращает пары (индекс, объект); индекс используется для
        # обращения к соответствующему элементу списка risk_orig
        table_original_rows.append({
            'command':     cmd.command,
            'frequency':   cmd.frequency,
            'criticality': cmd.criticality,
            'risk':        round(risk_orig[i], 2),  # round() до 2 знаков для отображения
            'status':      cmd.status,
        })

    crit_enh = [c * 1.2 if c > 0.5 else c for c in [cmd.criticality for cmd in commands]]
    # Вложенное list comprehension: сначала извлекает criticality всех команд,
    # затем применяет коэффициент усиления ×1.2 к командам с C > 0.5

    table_enhanced_rows = []
    for i, cmd in enumerate(commands):
        table_enhanced_rows.append({
            'command':         cmd.command,
            'frequency':       cmd.frequency,
            'criticality_enh': round(crit_enh[i], 2),
            'risk_enh':        round(risk_enh[i], 2),
            'status':          cmd.status,
        })

    ctx = {
        **_base_ctx(request),
        # ** — распаковка словаря; объединяет базовый контекст с контекстом страницы
        'table_original_rows': table_original_rows,
        'table_enhanced_rows': table_enhanced_rows,
        'bar_chart':  generate_bar_chart(risk_orig, "Индекс угрозы по командам"),
        'pie_chart':  generate_pie_chart(risk_orig, "Вклад команд в общий индекс угрозы"),
        'line_chart': generate_line_chart(risk_orig, risk_enh),
        # Три вызова возвращают Base64-строки PNG;
        # шаблон встраивает их как <img src="data:image/png;base64,{{ bar_chart }}">

        'total_commands':  commands.count(),
        'blocked_count':   commands.filter(status='blocked').count(),
        # Повторный filter() — Django добавляет WHERE к уже построенному QuerySet,
        # не дублируя исходную выборку
        'allowed_count':   commands.filter(status='allowed').count(),
        'monitored_count': commands.filter(status='monitored').count(),
    }
    return render(request, 'bmc_analyzer/index.html', ctx)
    # render() вызывает Template.render(ctx) и оборачивает HTML в HttpResponse (200)


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 4. ЖУРНАЛ СОБЫТИЙ БЕЗОПАСНОСТИ
# Отображает записи EventLog с фильтрацией по 4 параметрам и пагинацией;
# для каждой записи верифицирует целостность хеш-цепочки
# ════════════════════════════════════════════════════════════════════════════

@login_required
def logs_view(request):
    qs = EventLog.objects.all()
    # Базовый «ленивый» QuerySet; фильтры применяются цепочкой ниже

    event_type_filter = request.GET.get('event_type', '')
    date_from         = request.GET.get('date_from', '')
    date_to           = request.GET.get('date_to', '')
    username_filter   = request.GET.get('username', '')
    # request.GET — словарь параметров строки запроса (?key=value);
    # get(key, default) возвращает '' если параметр отсутствует

    if event_type_filter:
        qs = qs.filter(event_type=event_type_filter)
    if date_from:
        qs = qs.filter(timestamp__date__gte=date_from)
        # __date      — трансформация DateTimeField → Date (отсекает время)
        # __gte       — «greater than or equal» (≥), аналог SQL >=
    if date_to:
        qs = qs.filter(timestamp__date__lte=date_to)
        # __lte       — «less than or equal» (≤)
    if username_filter:
        qs = qs.filter(username__icontains=username_filter)
        # __icontains — подстрочный поиск без учёта регистра (SQL LIKE '%...%')

    paginator = Paginator(qs, 25)
    # Paginator(queryset, per_page): при обращении к странице добавляет LIMIT/OFFSET
    page_num  = request.GET.get('page', 1)
    page_obj  = paginator.get_page(page_num)
    # get_page() безопасна: при невалидном номере возвращает первую страницу
    # (в отличие от page(), которая бросает InvalidPage)

    entries_with_verify = []
    for entry in page_obj:
        entries_with_verify.append({
            'entry':   entry,
            'hash_ok': entry.verify_hash(),
            # verify_hash() пересчитывает SHA-256 и сравнивает с entry_hash в БД;
            # False означает, что запись была изменена вне штатного интерфейса
        })

    ctx = {
        **_base_ctx(request),
        'page_obj':            page_obj,
        'entries_with_verify': entries_with_verify,
        'event_types':         EventLog.EVENT_TYPES,
        # Передаём список типов в шаблон для построения выпадающего списка фильтра
        'event_type_filter':   event_type_filter,
        'date_from':           date_from,
        'date_to':             date_to,
        'username_filter':     username_filter,
        'total_count':         qs.count(),
        # qs.count() — выполняет COUNT(*) с применёнными фильтрами
    }
    return render(request, 'bmc_analyzer/logs.html', ctx)


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 5. КОНТРОЛЬ ЦЕЛОСТНОСТИ КОМПОНЕНТОВ (внутренний, не используется в UI)
# Эндпоинты сохранены для API-доступа; раздел скрыт из навигации
# ════════════════════════════════════════════════════════════════════════════

@login_required
def integrity_view(request):
    records      = IntegrityRecord.objects.all()
    ok_count      = records.filter(last_status='ok').count()
    fail_count    = records.filter(last_status='fail').count()
    unknown_count = records.filter(last_status='unknown').count()
    ctx = {
        **_base_ctx(request),
        'records':       records,
        'ok_count':      ok_count,
        'fail_count':    fail_count,
        'unknown_count': unknown_count,
    }
    return render(request, 'bmc_analyzer/integrity.html', ctx)


@login_required
def run_integrity_check_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
        # 405 Method Not Allowed — явный сигнал клиенту об ошибке протокола
    username = request.user.username
    ip       = get_client_ip(request)
    results  = run_integrity_check(username=username)

    log_event(
        'integrity_ok' if all(r['status'] == 'ok' for r in results) else 'integrity_fail',
        # all() возвращает True только если все элементы генератора истинны
        username=username, ip_address=ip,
        details={'results': results, 'total': len(results)}
    )
    return JsonResponse({'results': results})


@login_required
def simulate_integrity_fail(request):
    # Симулирует нарушение целостности: заменяет current_hash случайным значением
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    component_id = request.POST.get('component_id')
    try:
        record = IntegrityRecord.objects.get(pk=component_id)
        import hashlib, secrets
        record.current_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        # secrets.token_bytes(32) — криптографически стойкий генератор случайных байтов;
        # hexdigest() преобразует SHA-256 в 64-символьную hex-строку
        record.save(update_fields=['current_hash'])
        # update_fields= — обновляет только указанный столбец в SQL UPDATE
        return JsonResponse({'ok': True, 'component': record.component})
    except IntegrityRecord.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)


@login_required
def restore_integrity(request):
    # Восстанавливает целостность: возвращает current_hash = reference_hash
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    component_id = request.POST.get('component_id')
    try:
        record = IntegrityRecord.objects.get(pk=component_id)
        record.current_hash = record.reference_hash  # Восстанавливаем эталонное значение
        record.last_status  = 'unknown'              # Сбрасываем статус до следующей проверки
        record.save(update_fields=['current_hash', 'last_status'])
        return JsonResponse({'ok': True, 'component': record.component})
    except IntegrityRecord.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 6. УПРАВЛЕНИЕ ОПОВЕЩЕНИЯМИ
# CRUD-операции над Alert: просмотр, закрытие одного, закрытие всех
# ════════════════════════════════════════════════════════════════════════════

@login_required
def alerts_view(request):
    show = request.GET.get('show', 'active')
    # Параметр ?show= управляет фильтром отображаемых оповещений

    if show == 'all':
        alerts = Alert.objects.all()
    elif show == 'dismissed':
        alerts = Alert.objects.filter(dismissed_at__isnull=False)
        # __isnull=False — аналог SQL WHERE dismissed_at IS NOT NULL
    else:
        alerts = Alert.objects.filter(dismissed_at__isnull=True)
        # По умолчанию показываем только активные (не закрытые) оповещения

    ctx = {
        **_base_ctx(request),
        'alerts': alerts,
        'show':   show,
        'critical_count': Alert.objects.filter(dismissed_at__isnull=True, severity='critical').count(),
        'warning_count':  Alert.objects.filter(dismissed_at__isnull=True, severity='warning').count(),
        'info_count':     Alert.objects.filter(dismissed_at__isnull=True, severity='info').count(),
        # Три отдельных count() — каждый выполняет свой COUNT(*) запрос к БД
    }
    return render(request, 'bmc_analyzer/alerts.html', ctx)


@login_required
def dismiss_alert(request, alert_id):
    # Закрывает одно оповещение; вызывается AJAX-запросом из шаблона
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    alert = get_object_or_404(Alert, pk=alert_id)
    # pk= — универсальный alias для первичного ключа (эквивалентно id=)

    alert.dismissed_at = timezone.now()
    # timezone.now() — текущее время с учётом TIME_ZONE из settings;
    # datetime.now() без timezone дал бы «наивный» объект без зоны

    alert.dismissed_by = request.user
    # request.user — объект аутентифицированного пользователя из сессии

    alert.is_read = True
    alert.save()
    # Полное сохранение всех полей объекта одним SQL UPDATE

    log_event('alert_created', username=request.user.username,
              ip_address=get_client_ip(request),
              details={'action': 'dismiss', 'alert_id': alert_id, 'title': alert.title})
    return JsonResponse({'ok': True})
    # Ответ AJAX-вызову: статус 200 и JSON-тело; браузер обновляет UI без перезагрузки


@login_required
def dismiss_all_alerts(request):
    # Массово закрывает все активные оповещения одним SQL-запросом
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    now = timezone.now()
    updated = Alert.objects.filter(dismissed_at__isnull=True).update(
        dismissed_at=now, is_read=True, dismissed_by=request.user
    )
    # QuerySet.update() — один SQL UPDATE вместо N вызовов save();
    # возвращает количество изменённых строк

    return JsonResponse({'ok': True, 'dismissed': updated})
    # dismissed — число закрытых оповещений; передаётся в JS для обновления счётчика


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 7. УПРАВЛЕНИЕ ПОЛИТИКАМИ КОМАНД
# Просмотр и изменение статусов команд через HTML-форму
# ════════════════════════════════════════════════════════════════════════════

@login_required
def policies_view(request):
    if request.method == 'POST' and 'update_status' in request.POST:
        # request.POST — словарь данных HTML-формы (application/x-www-form-urlencoded);
        # проверка 'update_status' in request.POST определяет тип операции по наличию ключа

        policy_id  = request.POST.get('policy_id')
        new_status = request.POST.get('new_status')

        if new_status in ('allowed', 'blocked', 'monitored'):
            # Whitelist-валидация: принимаем только три допустимых значения
            policy     = get_object_or_404(CommandPolicy, pk=policy_id)
            old_status = policy.status
            policy.status = new_status
            policy.save(update_fields=['status'])
            # update_fields= ограничивает UPDATE только столбцом status;
            # исключает случайную перезапись других полей

            log_event('policy_change', username=request.user.username,
                      ip_address=get_client_ip(request),
                      command=policy.command,
                      details={'old_status': old_status, 'new_status': new_status})

            messages.success(request,
                f'Статус команды «{policy.command}» изменён на «{policy.get_status_display()}».')
            # messages.success() сохраняет сообщение в сессии;
            # отображается в шаблоне base.html при следующем запросе

        return redirect('policies')
        # redirect() с именем URL реализует паттерн Post/Redirect/Get:
        # предотвращает повторную отправку формы при обновлении страницы

    policies = CommandPolicy.objects.all().order_by('command')
    ctx = {
        **_base_ctx(request),
        'policies':      policies,
        'commands_json': list(policies.values_list('command', flat=True)),
        # values_list('command', flat=True) — плоский список строк вместо кортежей;
        # list() материализует QuerySet для JSON-сериализации в шаблоне
        'blocked_count':   policies.filter(status='blocked').count(),
        'allowed_count':   policies.filter(status='allowed').count(),
        'monitored_count': policies.filter(status='monitored').count(),
    }
    return render(request, 'bmc_analyzer/policies.html', ctx)


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 8. AJAX-СИМУЛЯТОР BMC-КОМАНДЫ
# Проверяет команду по политикам, записывает событие в журнал,
# при необходимости создаёт оповещение и возвращает JSON-результат
# ════════════════════════════════════════════════════════════════════════════

@login_required
def simulate_command_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    import socket   # Используется для валидации IP-адреса через inet_pton

    cmd_name = request.POST.get('command', '').strip()
    # strip() удаляет случайные пробелы по краям строки пользовательского ввода

    if not cmd_name:
        return JsonResponse({'error': 'Команда не указана'}, status=400)
        # 400 Bad Request — клиент отправил некорректный запрос

    src_ip = get_client_ip(request)
    # IP-адрес клиента из заголовка X-Forwarded-For (с учётом Replit-прокси)

    status, policy = check_command_policy(cmd_name)
    # Поиск команды в CommandPolicy без учёта регистра;
    # status = 'allowed' | 'blocked' | 'monitored' | 'unknown'

    username = request.user.username

    event_map = {
        # Словарь сопоставления статуса политики → типу события журнала
        'blocked':   'cmd_blocked',
        'allowed':   'cmd_allowed',
        'monitored': 'cmd_monitored',
        'unknown':   'cmd_monitored',  # Неизвестные команды фиксируются как мониторинг
    }
    event_type = event_map.get(status, 'cmd_monitored')
    # dict.get(key, default) — возвращает default если ключ отсутствует

    details = {
        'result':   status,
        'src_ip':   src_ip,
        'protocol': 'IPMI/RMCP+',
    }
    if policy:
        details['criticality'] = str(policy.criticality)
        details['description'] = policy.description
        # Дополняем детали данными политики только если она найдена

    log_event(event_type, username=username, ip_address=src_ip,
              command=cmd_name, details=details)
    # Каждый вызов симулятора оставляет запись в защищённом журнале

    if status == 'blocked':
        create_alert(
            'warning',
            f'Попытка заблокированной команды: {cmd_name}',
            f'Пользователь {username} ({src_ip}) попытался выполнить '
            f'заблокированную команду «{cmd_name}».',
        )
        # Оповещение создаётся только при попытке выполнить заблокированную команду

    return JsonResponse({
        'status':       status,
        'command':      cmd_name,
        'src_ip':       src_ip,
        'username':     username,
        'criticality':  policy.criticality if policy else None,
        # Тернарный оператор: None если policy не найдена
        'description':  policy.description if policy else '',
        'event_logged': True,
        'alert_created': status == 'blocked',
        # Булево выражение как значение — явный сигнал JS-коду на фронтенде
    })


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 9. AJAX-ЭНДПОИНТ СОЗДАНИЯ ПОЛИТИКИ КОМАНДЫ
# Валидирует входные данные и добавляет новую запись в CommandPolicy
# ════════════════════════════════════════════════════════════════════════════

@login_required
def add_policy(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    command = request.POST.get('command', '').strip()
    if not command:
        return JsonResponse({'error': 'Имя команды обязательно'}, status=400)

    if CommandPolicy.objects.filter(command__iexact=command).exists():
        # exists() — SELECT 1 LIMIT 1 без загрузки данных; эффективнее count() > 0
        return JsonResponse(
            {'error': f'Команда «{command}» уже существует в политиках'}, status=400
        )

    try:
        criticality = float(request.POST.get('criticality', '0.5'))
        criticality = max(0.0, min(1.0, criticality))
        # max/min зажимают значение в диапазон [0.0; 1.0] независимо от клиентского ввода
    except ValueError:
        criticality = 0.5   # Безопасное значение по умолчанию при некорректном вводе

    try:
        frequency = int(request.POST.get('frequency', '1'))
        frequency = max(1, frequency)   # Частота не может быть меньше 1
    except ValueError:
        frequency = 1

    status_val = request.POST.get('status', 'monitored')
    if status_val not in ('allowed', 'blocked', 'monitored'):
        status_val = 'monitored'   # Whitelist-валидация статуса

    description = request.POST.get('description', '').strip()

    policy = CommandPolicy.objects.create(
        # objects.create() — атомарный INSERT; возвращает созданный объект с заполненным id
        command=command, criticality=criticality,
        frequency=frequency, status=status_val, description=description,
    )

    log_event('policy_change', username=request.user.username,
              ip_address=get_client_ip(request), command=command,
              details={'action': 'created', 'status': status_val,
                       'criticality': criticality, 'frequency': frequency})

    return JsonResponse({
        'ok': True, 'id': policy.id,
        'command': policy.command, 'status': policy.status,
        'criticality': policy.criticality, 'frequency': policy.frequency,
        'description': policy.description,
        # Возвращаем все поля созданного объекта: JS-код вставляет строку в таблицу без перезагрузки
    })


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 10. AJAX-ЭНДПОИНТ УДАЛЕНИЯ ПОЛИТИКИ КОМАНДЫ
# ════════════════════════════════════════════════════════════════════════════

@login_required
def delete_policy(request, policy_id):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    policy = get_object_or_404(CommandPolicy, pk=policy_id)
    command_name = policy.command   # Сохраняем имя до удаления:
    policy.delete()                 # после delete() атрибуты объекта становятся None
    # delete() выполняет SQL DELETE и каскадно удаляет связанные записи (если есть)

    log_event('policy_change', username=request.user.username,
              ip_address=get_client_ip(request),
              command=command_name, details={'action': 'deleted'})

    return JsonResponse({'ok': True, 'command': command_name})
    # Возвращаем имя команды: JS-код использует его для подтверждения в UI


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 11. API СТАТУСА БЕЗОПАСНОСТИ ПРОТОКОЛА
# Возвращает JSON с текущим состоянием HTTPS, HSTS и статистикой системы
# ════════════════════════════════════════════════════════════════════════════

@login_required
def security_status(request):
    is_secure    = request.is_secure()
    # is_secure() возвращает True если запрос пришёл по HTTPS;
    # учитывает SECURE_PROXY_SSL_HEADER из settings

    proto        = request.META.get('HTTP_X_FORWARDED_PROTO', 'unknown')
    https_active = is_secure or proto == 'https'
    # Двойная проверка: через Django-метод И через заголовок прокси

    return JsonResponse({
        'ssl_redirect':   True,
        'hsts_active':    bool(getattr(django_settings, 'SECURE_HSTS_SECONDS', 0)),
        # getattr с default=0 безопасно читает настройку; bool() приводит к True/False
        'secure_cookies': getattr(django_settings, 'SESSION_COOKIE_SECURE', False),
        'protocol':       'HTTPS' if https_active else 'HTTP',
        'is_secure':      https_active,
        'version':        '2.0.0',
        'hsts_enabled':   True,
        'security_headers': [
            # Перечень заголовков, устанавливаемых SecurityHeadersMiddleware
            'Strict-Transport-Security', 'X-Content-Type-Options',
            'X-XSS-Protection', 'Referrer-Policy',
            'Permissions-Policy', 'Content-Security-Policy',
        ],
        'stats': {
            'total_events':    EventLog.objects.count(),
            # count() без фильтров — COUNT(*) по всей таблице
            'blocked_commands': EventLog.objects.filter(event_type='cmd_blocked').count(),
            'integrity_fails':  EventLog.objects.filter(event_type='integrity_fail').count(),
            'active_alerts':    Alert.objects.filter(dismissed_at__isnull=True).count(),
        }
    })
