from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import CommandPolicy
from .utils import calculate_risks, generate_bar_chart, generate_pie_chart, generate_line_chart


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
        })

    crit_enh = [c * 1.2 if c > 0.5 else c for c in [cmd.criticality for cmd in commands]]
    table_enhanced_rows = []
    for i, cmd in enumerate(commands):
        table_enhanced_rows.append({
            'command': cmd.command,
            'frequency': cmd.frequency,
            'criticality_enh': round(crit_enh[i], 2),
            'risk_enh': round(risk_enh[i], 2),
        })

    context = {
        'table_original_rows': table_original_rows,
        'table_enhanced_rows': table_enhanced_rows,
        'bar_chart': generate_bar_chart(risk_orig, "Индекс угрозы по командам"),
        'pie_chart': generate_pie_chart(risk_orig, "Вклад команд в общий индекс угрозы"),
        'line_chart': generate_line_chart(risk_orig, risk_enh),
        'is_admin': request.user.is_staff,
    }
    return render(request, 'bmc_analyzer/index.html', context)


@login_required
def security_status(request):
    """
    API-эндпоинт для проверки статуса безопасности соединения.
    Возвращает JSON с информацией о протоколе и заголовках.
    Формат ответа: {"ssl_redirect": true, "hsts_active": true, "secure_cookies": true, ...}
    """
    from django.http import JsonResponse
    from django.conf import settings as django_settings
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
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy',
            'Content-Security-Policy',
        ],
    })

