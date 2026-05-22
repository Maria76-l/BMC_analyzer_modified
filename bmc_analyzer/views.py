from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone
from django.contrib import messages
from django.core.paginator import Paginator
from django.conf import settings as django_settings

from .models import CommandPolicy, EventLog, IntegrityRecord, Alert
from .utils import (
    calculate_risks, generate_bar_chart, generate_pie_chart, generate_line_chart,
    log_event, check_command_policy, run_integrity_check, create_alert, get_client_ip
)


def _base_ctx(request):
    unread_alerts = Alert.objects.filter(dismissed_at__isnull=True).count()
    return {'is_admin': request.user.is_staff, 'unread_alerts': unread_alerts}


# ─── Main dashboard ──────────────────────────────────────────────────────────

@login_required
def index(request):
    commands = CommandPolicy.objects.all().order_by('id')
    risk_orig, risk_enh, df_orig, df_enh = calculate_risks(commands)

    table_original_rows = []
    for i, cmd in enumerate(commands):
        table_original_rows.append({
            'command': cmd.command,
            'frequency': cmd.frequency,
            'criticality': cmd.criticality,
            'risk': round(risk_orig[i], 2),
            'status': cmd.status,
        })

    crit_enh = [c * 1.2 if c > 0.5 else c for c in [cmd.criticality for cmd in commands]]
    table_enhanced_rows = []
    for i, cmd in enumerate(commands):
        table_enhanced_rows.append({
            'command': cmd.command,
            'frequency': cmd.frequency,
            'criticality_enh': round(crit_enh[i], 2),
            'risk_enh': round(risk_enh[i], 2),
            'status': cmd.status,
        })

    ctx = {
        **_base_ctx(request),
        'table_original_rows': table_original_rows,
        'table_enhanced_rows': table_enhanced_rows,
        'bar_chart': generate_bar_chart(risk_orig, "Индекс угрозы по командам"),
        'pie_chart': generate_pie_chart(risk_orig, "Вклад команд в общий индекс угрозы"),
        'line_chart': generate_line_chart(risk_orig, risk_enh),
        'total_commands': commands.count(),
        'blocked_count': commands.filter(status='blocked').count(),
        'allowed_count': commands.filter(status='allowed').count(),
        'monitored_count': commands.filter(status='monitored').count(),
    }
    return render(request, 'bmc_analyzer/index.html', ctx)


# ─── Event log ───────────────────────────────────────────────────────────────

@login_required
def logs_view(request):
    qs = EventLog.objects.all()

    event_type_filter = request.GET.get('event_type', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    username_filter = request.GET.get('username', '')

    if event_type_filter:
        qs = qs.filter(event_type=event_type_filter)
    if date_from:
        qs = qs.filter(timestamp__date__gte=date_from)
    if date_to:
        qs = qs.filter(timestamp__date__lte=date_to)
    if username_filter:
        qs = qs.filter(username__icontains=username_filter)

    paginator = Paginator(qs, 25)
    page_num = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_num)

    # Verify hash chain integrity for displayed entries
    entries_with_verify = []
    for entry in page_obj:
        entries_with_verify.append({
            'entry': entry,
            'hash_ok': entry.verify_hash(),
        })

    ctx = {
        **_base_ctx(request),
        'page_obj': page_obj,
        'entries_with_verify': entries_with_verify,
        'event_types': EventLog.EVENT_TYPES,
        'event_type_filter': event_type_filter,
        'date_from': date_from,
        'date_to': date_to,
        'username_filter': username_filter,
        'total_count': qs.count(),
    }
    return render(request, 'bmc_analyzer/logs.html', ctx)


# ─── Integrity monitoring ────────────────────────────────────────────────────

@login_required
def integrity_view(request):
    records = IntegrityRecord.objects.all()
    ok_count = records.filter(last_status='ok').count()
    fail_count = records.filter(last_status='fail').count()
    unknown_count = records.filter(last_status='unknown').count()

    ctx = {
        **_base_ctx(request),
        'records': records,
        'ok_count': ok_count,
        'fail_count': fail_count,
        'unknown_count': unknown_count,
    }
    return render(request, 'bmc_analyzer/integrity.html', ctx)


@login_required
def run_integrity_check_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    username = request.user.username
    ip = get_client_ip(request)
    results = run_integrity_check(username=username)
    log_event('integrity_ok' if all(r['status'] == 'ok' for r in results) else 'integrity_fail',
              username=username, ip_address=ip,
              details={'results': results, 'total': len(results)})
    return JsonResponse({'results': results})


@login_required
def simulate_integrity_fail(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    component_id = request.POST.get('component_id')
    try:
        record = IntegrityRecord.objects.get(pk=component_id)
        import hashlib, secrets
        record.current_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        record.save(update_fields=['current_hash'])
        return JsonResponse({'ok': True, 'component': record.component})
    except IntegrityRecord.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)


@login_required
def restore_integrity(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    component_id = request.POST.get('component_id')
    try:
        record = IntegrityRecord.objects.get(pk=component_id)
        record.current_hash = record.reference_hash
        record.last_status = 'unknown'
        record.save(update_fields=['current_hash', 'last_status'])
        return JsonResponse({'ok': True, 'component': record.component})
    except IntegrityRecord.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)


# ─── Alerts ──────────────────────────────────────────────────────────────────

@login_required
def alerts_view(request):
    show = request.GET.get('show', 'active')
    if show == 'all':
        alerts = Alert.objects.all()
    elif show == 'dismissed':
        alerts = Alert.objects.filter(dismissed_at__isnull=False)
    else:
        alerts = Alert.objects.filter(dismissed_at__isnull=True)

    ctx = {
        **_base_ctx(request),
        'alerts': alerts,
        'show': show,
        'critical_count': Alert.objects.filter(dismissed_at__isnull=True, severity='critical').count(),
        'warning_count': Alert.objects.filter(dismissed_at__isnull=True, severity='warning').count(),
        'info_count': Alert.objects.filter(dismissed_at__isnull=True, severity='info').count(),
    }
    return render(request, 'bmc_analyzer/alerts.html', ctx)


@login_required
def dismiss_alert(request, alert_id):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    alert = get_object_or_404(Alert, pk=alert_id)
    alert.dismissed_at = timezone.now()
    alert.dismissed_by = request.user
    alert.is_read = True
    alert.save()
    log_event('alert_created', username=request.user.username,
              ip_address=get_client_ip(request),
              details={'action': 'dismiss', 'alert_id': alert_id, 'title': alert.title})
    return JsonResponse({'ok': True})


@login_required
def dismiss_all_alerts(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    now = timezone.now()
    updated = Alert.objects.filter(dismissed_at__isnull=True).update(
        dismissed_at=now, is_read=True, dismissed_by=request.user
    )
    return JsonResponse({'ok': True, 'dismissed': updated})


# ─── Command policies ────────────────────────────────────────────────────────

@login_required
def policies_view(request):
    policies = CommandPolicy.objects.all()
    simulate_result = None

    if request.method == 'POST' and 'simulate' in request.POST:
        cmd_name = request.POST.get('command_name', '').strip()
        src_ip = request.POST.get('src_ip', '').strip() or get_client_ip(request)
        if cmd_name:
            status, policy = check_command_policy(cmd_name)
            username = request.user.username

            if status == 'blocked':
                event_type = 'cmd_blocked'
                log_event(event_type, username=username, ip_address=src_ip,
                          command=cmd_name,
                          details={'result': 'blocked', 'policy': policy.description if policy else ''})
                create_alert('warning',
                             f'Попытка заблокированной команды: {cmd_name}',
                             f'Пользователь {username} ({src_ip}) попытался выполнить заблокированную команду «{cmd_name}».')
            elif status == 'allowed':
                event_type = 'cmd_allowed'
                log_event(event_type, username=username, ip_address=src_ip,
                          command=cmd_name, details={'result': 'allowed'})
            elif status == 'monitored':
                event_type = 'cmd_monitored'
                log_event(event_type, username=username, ip_address=src_ip,
                          command=cmd_name, details={'result': 'monitored'})
            else:
                event_type = 'cmd_monitored'
                log_event(event_type, username=username, ip_address=src_ip,
                          command=cmd_name, details={'result': 'unknown_command'})

            criticality = policy.criticality if policy else None
            simulate_result = {
                'command': cmd_name,
                'status': status,
                'src_ip': src_ip,
                'policy': policy,
                'criticality': criticality,
            }

    if request.method == 'POST' and 'update_status' in request.POST:
        policy_id = request.POST.get('policy_id')
        new_status = request.POST.get('new_status')
        if new_status in ('allowed', 'blocked', 'monitored'):
            policy = get_object_or_404(CommandPolicy, pk=policy_id)
            old_status = policy.status
            policy.status = new_status
            policy.save(update_fields=['status'])
            log_event('policy_change', username=request.user.username,
                      ip_address=get_client_ip(request),
                      command=policy.command,
                      details={'old_status': old_status, 'new_status': new_status})
            messages.success(request, f'Статус команды «{policy.command}» изменён на «{policy.get_status_display()}».')
        return redirect('policies')

    ctx = {
        **_base_ctx(request),
        'policies': policies,
        'simulate_result': simulate_result,
        'blocked_count': policies.filter(status='blocked').count(),
        'allowed_count': policies.filter(status='allowed').count(),
        'monitored_count': policies.filter(status='monitored').count(),
    }
    return render(request, 'bmc_analyzer/policies.html', ctx)


# ─── Security status API ──────────────────────────────────────────────────────

@login_required
def security_status(request):
    is_secure = request.is_secure()
    proto = request.META.get('HTTP_X_FORWARDED_PROTO', 'unknown')
    https_active = is_secure or proto == 'https'
    return JsonResponse({
        'ssl_redirect': True,
        'hsts_active': bool(getattr(django_settings, 'SECURE_HSTS_SECONDS', 0)),
        'secure_cookies': getattr(django_settings, 'SESSION_COOKIE_SECURE', False),
        'protocol': 'HTTPS' if https_active else 'HTTP',
        'is_secure': https_active,
        'version': '2.0.0',
        'hsts_enabled': True,
        'security_headers': [
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy',
            'Content-Security-Policy',
        ],
        'stats': {
            'total_events': EventLog.objects.count(),
            'blocked_commands': EventLog.objects.filter(event_type='cmd_blocked').count(),
            'integrity_fails': EventLog.objects.filter(event_type='integrity_fail').count(),
            'active_alerts': Alert.objects.filter(dismissed_at__isnull=True).count(),
        }
    })
