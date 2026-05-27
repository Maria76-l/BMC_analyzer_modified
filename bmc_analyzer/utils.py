# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 1. ИМПОРТЫ И КОНФИГУРАЦИЯ MATPLOTLIB
# ════════════════════════════════════════════════════════════════════════════

import hashlib      # Стандартная библиотека: SHA-256 для хеш-цепочки журнала
import json         # Сериализация снапшота события перед хешированием
import io           # BytesIO — буфер в оперативной памяти для PNG без записи на диск
import base64       # Кодирование PNG-байтов в Base64-строку для встраивания в HTML
from datetime import datetime   # Метка времени в снапшоте события журнала

from sympy import symbols       # symbols() создаёт символьные переменные для формулы R = C × F
import pandas as pd             # DataFrame — табличная структура для данных анализа угроз
import matplotlib
matplotlib.use('Agg')           # Принудительно устанавливает бэкенд без GUI (без экрана);
                                # обязательно для серверной генерации — X11/Wayland недоступны
import matplotlib.pyplot as plt # Высокоуровневый API построения графиков


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 2. РАСЧЁТ ИНДЕКСА УГРОЗЫ
# Вычисляет R = C × F для каждой команды в базовом и усиленном сценариях
# ════════════════════════════════════════════════════════════════════════════

def calculate_risks(commands_qs):
    C, F = symbols('C F')
    # symbols() возвращает символьные объекты SymPy; запись C, F = symbols('C F')
    # создаёт два символа одним вызовом

    risk_formula = C * F
    # Аналитическое выражение формулы риска; SymPy хранит его как абстрактное
    # синтаксическое дерево, а не как числовое значение — позволяет подставлять
    # разные значения переменных без переопределения формулы

    commands, freq, crit = [], [], []
    for item in commands_qs:
        commands.append(item.command)
        freq.append(item.frequency)
        crit.append(item.criticality)

    risk_original = [
        float(risk_formula.subs({C: c, F: f}))
        # subs() — метод SymPy для подстановки конкретных значений в символьное выражение;
        # возвращает SymPy-число; float() приводит к стандартному Python float
        for f, c in zip(freq, crit)   # zip() объединяет два списка в пары (f, c)
    ]

    crit_enh = [c * 1.2 if c > 0.5 else c for c in crit]
    # Усиленный сценарий: команды с C > 0.5 получают коэффициент ×1.2,
    # моделируя рост угрозы при изменении контекста эксплуатации

    risk_enhanced = [
        float(risk_formula.subs({C: c, F: f}))
        for f, c in zip(freq, crit_enh)
    ]

    df_orig = pd.DataFrame({
        # DataFrame() — основная структура Pandas; создаёт двумерную таблицу
        # из словаря {имя_столбца: список_значений}
        '№':                     range(1, len(commands) + 1),
        'Команда':               commands,
        'Частота (F)':           freq,
        'Критичность (C)':       crit,
        'Индекс угрозы (R=C×F)': risk_original,
    })

    df_enh = pd.DataFrame({
        '№':                          range(1, len(commands) + 1),
        'Команда':                    commands,
        'Частота (F)':                freq,
        'Критичность (усиленная)':    crit_enh,
        'Индекс угрозы (усиленный)':  risk_enhanced,
    })

    return risk_original, risk_enhanced, df_orig, df_enh


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 3. ГЕНЕРАЦИЯ ГРАФИКОВ И СЕРИАЛИЗАЦИЯ В BASE64
# Строит три вида визуализаций и возвращает их как Base64-строки
# для прямого встраивания в HTML без сохранения файлов на диск
# ════════════════════════════════════════════════════════════════════════════

def _fig_to_base64():
    # Приватная вспомогательная функция (имя начинается с _);
    # вызывается из трёх публичных функций генерации графиков

    buf = io.BytesIO()
    # BytesIO — файлоподобный объект в оперативной памяти;
    # исключает запись PNG на диск и работу с файловой системой

    plt.savefig(buf, format='png', dpi=100)
    # savefig() сохраняет текущую фигуру Matplotlib в буфер;
    # dpi=100 — достаточное разрешение для экранного отображения

    buf.seek(0)
    # seek(0) перемещает позицию чтения в начало буфера после записи

    img = base64.b64encode(buf.read()).decode('utf-8')
    # b64encode() кодирует байты в Base64;
    # decode('utf-8') переводит bytes → str для вставки в атрибут src=""

    plt.close()
    # close() освобождает память фигуры Matplotlib;
    # критично в серверной среде для предотвращения утечек памяти
    return img


def generate_bar_chart(data, title="Индекс угрозы по командам"):
    plt.figure(figsize=(12, 6))   # figsize задаёт размер холста в дюймах

    colors = ['#28a745' if x <= 1.0 else '#ffc107' if x <= 2.0 else '#dc3545'
              for x in data]
    # Условное окрашивание столбцов по порогам риска:
    # зелёный (≤1.0) → жёлтый (≤2.0) → красный (>2.0)

    bars = plt.bar(range(1, len(data) + 1), data, color=colors,
                   edgecolor='black', linewidth=0.8)
    # bar() строит столбчатую диаграмму; первый аргумент — позиции по X,
    # второй — высоты столбцов; возвращает коллекцию объектов Rectangle

    for bar, val in zip(bars, data):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                 f'{val:.2f}', ha='center', va='bottom', fontsize=9, fontweight='bold')
        # text() добавляет подпись над каждым столбцом;
        # get_x() + get_width()/2 вычисляет горизонтальный центр столбца

    plt.xlabel('Номер команды', fontsize=11)
    plt.ylabel('Индекс угрозы (R = C × F)', fontsize=11)
    plt.title(title, fontsize=14, fontweight='bold')
    plt.xticks(range(1, len(data) + 1))  # Подписи делений оси X: 1, 2, 3, …
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    # grid() с axis='y' рисует только горизонтальные линии сетки;
    # alpha=0.6 делает их полупрозрачными

    plt.ylim(0, max(data) * 1.15 if data else 1)
    # ylim() задаёт диапазон оси Y; ×1.15 добавляет 15% запас выше максимума

    plt.tight_layout()
    # tight_layout() автоматически подбирает отступы, исключая обрезку подписей
    return _fig_to_base64()


def generate_pie_chart(data, title="Вклад команд в общий индекс угрозы"):
    filtered = [(val, idx) for idx, val in enumerate(data) if val > 0]
    # enumerate() возвращает пары (индекс, значение); фильтруем нулевые сегменты

    if not filtered:
        plt.figure(figsize=(8, 8))
        plt.pie([1], labels=['Нет данных'], autopct='%1.1f%%')
        plt.title(title)
        return _fig_to_base64()

    values, indices = zip(*filtered)
    # zip(*iterable) — «распаковка транспозиции»: список пар → два отдельных кортежа

    labels = [str(i + 1) for i in indices]

    if len(values) > 5:
        # Группировка хвоста: топ-5 показываем отдельно, остальные — в «Прочие»
        sorted_data = sorted(zip(values, labels), reverse=True)
        top5 = sorted_data[:5]
        others_val = sum(v for v, _ in sorted_data[5:])
        values = [v for v, _ in top5] + [others_val]
        labels = [lb for _, lb in top5] + [f'Остальные ({len(sorted_data) - 5})']

    def autopct_format(pct):
        return f'{pct:.1f}%' if pct > 3 else ''
        # Скрываем подпись для сегментов < 3% — иначе надписи перекрываются

    plt.figure(figsize=(8, 8))
    wedges, texts, autotexts = plt.pie(
        values, labels=labels,
        autopct=autopct_format,     # Функция форматирования процентных подписей
        startangle=90,              # Первый сегмент начинается сверху (12 часов)
        wedgeprops={'edgecolor': 'white', 'linewidth': 1.5}
    )
    for autotext in autotexts:
        autotext.set_fontsize(9)
        autotext.set_weight('bold')

    plt.title(title, fontsize=14, fontweight='bold')
    plt.axis('equal')   # Делает круговую диаграмму идеально круглой (не эллипсом)
    plt.tight_layout()
    return _fig_to_base64()


def generate_line_chart(risk_orig, risk_enh):
    plt.figure(figsize=(12, 6))
    x = range(1, len(risk_orig) + 1)

    plt.plot(x, risk_orig, label='Исходный индекс угрозы',
             marker='o', linestyle='-', color='#007bff', linewidth=2, markersize=8)
    # plot() рисует линейный график; marker='o' — кружок в каждой точке

    plt.plot(x, risk_enh, label='Усиленный индекс угрозы',
             marker='s', linestyle='--', color='#fd7e14', linewidth=2, markersize=8)
    # marker='s' — квадрат; linestyle='--' — пунктирная линия

    plt.xlabel('Номер команды', fontsize=11)
    plt.ylabel('Индекс угрозы', fontsize=11)
    plt.title('Сравнение исходного и усиленного индекса угрозы',
              fontsize=14, fontweight='bold')
    plt.legend()    # legend() отображает легенду с метками из аргументов label=
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.xticks(x)
    plt.tight_layout()
    return _fig_to_base64()


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 4. ХЕШ-ЦЕПОЧКА ЖУРНАЛА БЕЗОПАСНОСТИ
# Реализует атомарное добавление записи в защищённый журнал событий:
# каждый entry_hash зависит от prev_hash, образуя неизменяемую цепочку
# ════════════════════════════════════════════════════════════════════════════

def _compute_entry_hash(entry_data: dict, prev_hash: str) -> str:
    # Вычисляет SHA-256 хеш текущей записи на основе её данных и хеша предыдущей

    raw = json.dumps(
        entry_data,
        ensure_ascii=False,  # Сохраняет кириллицу как есть, не экранирует \uXXXX
        sort_keys=True,      # Одинаковый порядок ключей — критично для воспроизводимости хеша
        default=str          # Сериализует нестандартные типы (datetime, Decimal) через str()
    ) + prev_hash
    # Конкатенация JSON-снапшота с prev_hash «связывает» текущую запись с предыдущей

    return hashlib.sha256(   # sha256() инициализирует объект хеш-функции SHA-256
        raw.encode('utf-8')  # encode('utf-8') переводит строку в байты для хеш-функции
    ).hexdigest()
    # hexdigest() возвращает 64-символьную шестнадцатеричную строку


def log_event(event_type, username='', ip_address=None, command='', details=None):
    # Основная точка входа для записи любого события безопасности.
    # Вызывается из views.py и utils.py при каждом значимом действии.

    from .models import EventLog   # Отложенный импорт предотвращает циклические зависимости

    if details is None:
        details = {}   # Не используем {} как аргумент по умолчанию — изменяемый default

    last = EventLog.objects.order_by('-id').first()
    # order_by('-id').first() — эффективнее, чем latest('timestamp'):
    # id — первичный ключ с индексом B-Tree, гарантирует порядок вставки

    prev_hash = last.entry_hash if last else '0' * 64
    # Если журнал пуст — «нулевой блок» из 64 нулей как genesis-запись цепочки

    entry_data = {
        # Снапшот данных для хеширования — должен совпадать с составом в verify_hash()
        'event_type': event_type,
        'username':   username,
        'ip_address': str(ip_address) if ip_address else '',
        'command':    command,
        'details':    details,
        'timestamp':  datetime.utcnow().isoformat(),
        # utcnow() — независимо от часового пояса сервера;
        # isoformat() даёт строку вида '2026-05-22T14:30:00.123456'
    }

    entry_hash = _compute_entry_hash(entry_data, prev_hash)
    # Хеш вычисляется до вызова objects.create():
    # если create() упадёт, некорректный хеш не попадёт в БД

    return EventLog.objects.create(
        # objects.create() — сочетание objects.build() + save();
        # выполняет один INSERT и возвращает созданный объект
        event_type=event_type,
        username=username,
        ip_address=ip_address if ip_address else None,
        # Явная проверка: пустая строка '' не является допустимым IP;
        # GenericIPAddressField принимает None, но не пустую строку
        command=command,
        details=details,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 5. ПРОВЕРКА КОМАНДЫ ПО ПОЛИТИКАМ БЕЗОПАСНОСТИ
# ════════════════════════════════════════════════════════════════════════════

def check_command_policy(command_name):
    # Ищет команду в базе политик и возвращает её статус и объект политики.
    # Вызывается симулятором и обработчиком реальных запросов.

    from .models import CommandPolicy   # Отложенный импорт

    try:
        policy = CommandPolicy.objects.get(command__iexact=command_name.strip())
        # objects.get() возбуждает DoesNotExist при отсутствии — намеренно
        # используется вместо filter().first(), чтобы различать «не найдено» от «найдено»;
        # __iexact — lookup без учёта регистра: "CHASSIS POWER OFF" == "chassis power off";
        # .strip() удаляет случайные пробелы по краям строки

        return policy.status, policy  # Кортеж (статус, объект политики)

    except CommandPolicy.DoesNotExist:
        return 'unknown', None   # Явный сигнал: команда вне определённых политик


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 6. ПРОВЕРКА ЦЕЛОСТНОСТИ КОМПОНЕНТОВ СЕРВЕРА
# ════════════════════════════════════════════════════════════════════════════

def run_integrity_check(username='system'):
    # Последовательно проверяет все компоненты в IntegrityRecord,
    # обновляет их статус, записывает события и создаёт оповещения при нарушениях.

    from .models import IntegrityRecord, Alert
    from django.utils import timezone   # timezone.now() — текущее время с учётом настроек

    results = []
    records = IntegrityRecord.objects.all()   # Получаем все контролируемые компоненты
    if not records.exists():
        # exists() выполняет SELECT 1 LIMIT 1 — эффективнее, чем count() > 0
        return []

    for record in records:
        current = record.current_hash if record.current_hash else record.reference_hash
        status  = 'ok' if current == record.reference_hash else 'fail'
        # Простое сравнение строк SHA-256: совпадает → ok, отличается → fail

        record.last_checked = timezone.now()
        record.last_status  = status
        record.save(update_fields=['last_checked', 'last_status'])
        # update_fields= ограничивает UPDATE только указанными столбцами;
        # исключает случайную перезапись других полей и снижает нагрузку на БД

        event_type = 'integrity_ok' if status == 'ok' else 'integrity_fail'
        log_event(
            event_type, username=username,
            details={
                'component':      record.component,
                'status':         status,
                'reference_hash': record.reference_hash[:16] + '...',
                # Первые 16 символов хеша достаточны для идентификации в журнале;
                # полный хеш не нужен — экономим место в details JSON
                'current_hash':   current[:16] + '...',
            }
        )

        if status == 'fail':
            Alert.objects.create(
                # Прямой create() вместо create_alert() — избегаем двойной записи в журнал
                severity='critical',
                title=f'Нарушение целостности: {record.component}',
                message=(
                    f'Обнаружено изменение хеш-суммы компонента «{record.component}».\n'
                    f'Эталон: {record.reference_hash[:32]}...\n'
                    f'Текущий: {current[:32]}...'
                ),
            )

        results.append({'component': record.component, 'status': status})

    return results


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 7. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ════════════════════════════════════════════════════════════════════════════

def create_alert(severity, title, message):
    # Создаёт оповещение и одновременно фиксирует факт его создания в журнале событий.

    from .models import Alert
    alert = Alert.objects.create(severity=severity, title=title, message=message)
    # objects.create() — атомарный INSERT; возвращает созданный объект

    log_event('alert_created', details={'severity': severity, 'title': title})
    # Записываем в журнал факт создания оповещения (но не сам объект Alert)
    return alert


def get_client_ip(request):
    # Извлекает реальный IP-адрес клиента с учётом работы за обратным прокси.

    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    # HTTP_X_FORWARDED_FOR — заголовок, который Replit-прокси добавляет к запросу;
    # содержит цепочку IP через запятую: «клиент, прокси1, прокси2»

    if x_forwarded:
        return x_forwarded.split(',')[0].strip()
        # split(',')[0] берёт первый IP в цепочке — IP исходного клиента;
        # strip() удаляет пробелы, которые некоторые прокси добавляют после запятой

    return request.META.get('REMOTE_ADDR', '127.0.0.1')
    # REMOTE_ADDR — прямой IP подключения; при работе за прокси это IP самого прокси,
    # поэтому используется только как запасной вариант
