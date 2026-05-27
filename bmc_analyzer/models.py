# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 1. ИМПОРТЫ И ЗАВИСИМОСТИ
# ════════════════════════════════════════════════════════════════════════════

import hashlib  # Стандартная библиотека SHA-256; используется в verify_hash()
import json     # Сериализация полей в строку перед хешированием

from django.db import models               # Базовый класс ORM; каждый подкласс — таблица БД
from django.contrib.auth.models import User  # Встроенная модель пользователя Django


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 2. МОДЕЛЬ ПОЛИТИКИ КОМАНДЫ BMC
# Хранит правило безопасности для одной IPMI/RMCP+-команды
# ════════════════════════════════════════════════════════════════════════════

class CommandPolicy(models.Model):

    STATUS_CHOICES = [
        # Кортежи (значение_в_БД, читаемая_метка) — Django автоматически
        # генерирует метод get_status_display() и валидирует допустимые значения
        ('allowed',   'Разрешено'),
        ('blocked',   'Заблокировано'),
        ('monitored', 'Мониторинг'),
    ]

    command = models.CharField(max_length=100, unique=True, verbose_name='Команда')
    # unique=True — ограничение на уровне БД: одна команда не может иметь два правила

    frequency = models.IntegerField(default=1, verbose_name='Частота (F)')
    # Ожидаемое число вызовов команды в сутки; компонент F в формуле R = C × F

    criticality = models.FloatField(default=0.5, verbose_name='Критичность (C)')
    # Коэффициент опасности команды в диапазоне [0.0; 1.0]; компонент C в R = C × F

    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='monitored',
        verbose_name='Статус'
    )
    # choices= ограничивает допустимые значения тремя константами из STATUS_CHOICES

    description = models.TextField(blank=True, verbose_name='Описание')
    # blank=True — поле не обязательно при валидации формы (допускает пустую строку)

    class Meta:
        verbose_name = 'Политика команды'
        verbose_name_plural = 'Политики команд'
        ordering = ['command']  # Сортировка по умолчанию при QuerySet без order_by()

    def __str__(self):
        return self.command  # Текстовое представление объекта в /admin/ и Django shell


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 3. МОДЕЛЬ ЖУРНАЛА СОБЫТИЙ С КРИПТОГРАФИЧЕСКОЙ ХЕШ-ЦЕПОЧКОЙ
# Каждая запись связана SHA-256 хешем с предыдущей — подделка одной записи
# делает все последующие верифицируемо недействительными
# ════════════════════════════════════════════════════════════════════════════

class EventLog(models.Model):

    EVENT_TYPES = [
        # Перечень допустимых типов событий; используется в choices= и фильтрах
        ('auth_success',   'Успешная аутентификация'),
        ('auth_fail',      'Ошибка аутентификации'),
        ('cmd_allowed',    'Команда разрешена'),
        ('cmd_blocked',    'Команда заблокирована'),
        ('cmd_monitored',  'Команда под мониторингом'),
        ('integrity_ok',   'Целостность в норме'),
        ('integrity_fail', 'Нарушение целостности'),
        ('alert_created',  'Создано оповещение'),
        ('policy_change',  'Изменение политики'),
    ]

    timestamp  = models.DateTimeField(auto_now_add=True, verbose_name='Время')
    # auto_now_add=True — поле заполняется автоматически моментом создания;
    # изменить его после создания записи невозможно

    event_type = models.CharField(max_length=30, choices=EVENT_TYPES,
                                  verbose_name='Тип события')

    username   = models.CharField(max_length=150, blank=True,
                                  verbose_name='Пользователь')

    ip_address = models.GenericIPAddressField(null=True, blank=True,
                                              verbose_name='IP-адрес')
    # GenericIPAddressField — валидирует формат IPv4 и IPv6 на уровне ORM и БД;
    # null=True разрешает хранить NULL (системные события без IP)

    command    = models.CharField(max_length=255, blank=True,
                                  verbose_name='Команда')

    details    = models.JSONField(default=dict, verbose_name='Детали')
    # JSONField — хранит произвольный Python-словарь как JSON в одном столбце БД;
    # default=dict создаёт новый пустой словарь для каждой записи

    prev_hash  = models.CharField(max_length=64, blank=True,
                                  verbose_name='Хеш предыдущей записи')
    # SHA-256 хеш (64 hex-символа) предшествующей записи — звено цепочки

    entry_hash = models.CharField(max_length=64, blank=True,
                                  verbose_name='Хеш записи')
    # SHA-256 хеш текущей записи, вычисленный из её содержимого + prev_hash

    class Meta:
        verbose_name = 'Событие'
        verbose_name_plural = 'Журнал событий'
        ordering = ['-timestamp']  # Минус = убывающий порядок (новейшие — первыми)

    def __str__(self):
        return f'[{self.timestamp}] {self.get_event_type_display()} — {self.username}'
        # get_event_type_display() — автогенерируемый Django метод;
        # возвращает читаемую метку из EVENT_TYPES по текущему значению event_type

    def verify_hash(self):
        # Верифицирует целостность одной записи: пересчитывает хеш и сравнивает
        # с сохранённым значением entry_hash

        payload = {
            # Формирует детерминированный снапшот полей — тот же состав и порядок,
            # что использовался при создании entry_hash в utils.log_event()
            'event_type': self.event_type,
            'username':   self.username,
            'ip_address': str(self.ip_address) if self.ip_address else '',
            'command':    self.command,
            'details':    self.details,
            'timestamp':  self.timestamp.isoformat() if self.timestamp else '',
        }

        raw = json.dumps(
            payload,
            ensure_ascii=False,  # Сохраняет кириллицу как есть, не экранирует \uXXXX
            sort_keys=True,      # Одинаковый порядок ключей — критично для воспроизводимости хеша
            default=str          # Сериализует нестандартные типы (datetime, Decimal) через str()
        ) + self.prev_hash       # Конкатенация с prev_hash «связывает» записи в цепочку

        return hashlib.sha256(   # sha256() — создаёт объект хеш-функции SHA-256
            raw.encode('utf-8')  # encode('utf-8') переводит строку в байты для хеш-функции
        ).hexdigest() == self.entry_hash
        # hexdigest() возвращает 64-символьную hex-строку; сравнивается с сохранённым хешем


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 4. МОДЕЛЬ КОНТРОЛЯ ЦЕЛОСТНОСТИ КОМПОНЕНТОВ
# Хранит эталонный и текущий SHA-256 хеш каждого контролируемого компонента
# ════════════════════════════════════════════════════════════════════════════

class IntegrityRecord(models.Model):

    STATUS_CHOICES = [
        ('ok',      'В норме'),
        ('fail',    'Нарушение'),
        ('unknown', 'Не проверено'),
    ]

    component      = models.CharField(max_length=200, unique=True,
                                      verbose_name='Компонент')
    description    = models.TextField(blank=True, verbose_name='Описание')

    reference_hash = models.CharField(max_length=64,
                                      verbose_name='Эталонный хеш (SHA-256)')
    # Эталонный хеш — записывается один раз при добавлении компонента;
    # является точкой доверия для всех последующих проверок

    current_hash   = models.CharField(max_length=64, blank=True,
                                      verbose_name='Текущий хеш')
    # Обновляется при каждой проверке; сравнивается с reference_hash

    last_checked   = models.DateTimeField(null=True, blank=True,
                                          verbose_name='Последняя проверка')
    last_status    = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='unknown',
        verbose_name='Статус'
    )
    created_at     = models.DateTimeField(auto_now_add=True)
    updated_at     = models.DateTimeField(auto_now=True)
    # auto_now=True — обновляется автоматически при каждом вызове save()

    class Meta:
        verbose_name = 'Запись целостности'
        verbose_name_plural = 'Контроль целостности'
        ordering = ['component']

    def __str__(self):
        return self.component


# ════════════════════════════════════════════════════════════════════════════
# РАЗДЕЛ 5. МОДЕЛЬ ОПОВЕЩЕНИЙ СИСТЕМЫ БЕЗОПАСНОСТИ
# Создаётся автоматически при блокировке опасных команд и нарушениях
# ════════════════════════════════════════════════════════════════════════════

class Alert(models.Model):

    SEVERITY_CHOICES = [
        ('info',     'Информация'),
        ('warning',  'Предупреждение'),
        ('critical', 'Критическое'),
    ]

    timestamp  = models.DateTimeField(auto_now_add=True, verbose_name='Время')
    severity   = models.CharField(
        max_length=20, choices=SEVERITY_CHOICES, default='info',
        verbose_name='Уровень'
    )
    title      = models.CharField(max_length=200, verbose_name='Заголовок')
    message    = models.TextField(verbose_name='Сообщение')
    is_read    = models.BooleanField(default=False, verbose_name='Прочитано')

    dismissed_at = models.DateTimeField(null=True, blank=True,
                                        verbose_name='Время закрытия')
    # Паттерн «nullable timestamp»: NULL = не закрыто, значение = закрыто;
    # сохраняет момент закрытия без отдельного булева поля

    dismissed_by = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL,        # При удалении пользователя — поле обнуляется,
        related_name='dismissed_alerts',  # запись оповещения сохраняется
        verbose_name='Закрыто'
    )

    class Meta:
        verbose_name = 'Оповещение'
        verbose_name_plural = 'Оповещения'
        ordering = ['-timestamp']

    def __str__(self):
        return f'[{self.severity.upper()}] {self.title}'

    @property
    def is_dismissed(self):
        # @property — позволяет обращаться как к атрибуту: alert.is_dismissed (без скобок);
        # удобно в шаблонах Django: {{ alert.is_dismissed }}
        return self.dismissed_at is not None
