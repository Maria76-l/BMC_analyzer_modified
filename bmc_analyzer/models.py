import hashlib
import json
from django.db import models
from django.contrib.auth.models import User


class CommandPolicy(models.Model):
    STATUS_CHOICES = [
        ('allowed', 'Разрешено'),
        ('blocked', 'Заблокировано'),
        ('monitored', 'Мониторинг'),
    ]
    command = models.CharField(max_length=100, unique=True, verbose_name='Команда')
    frequency = models.IntegerField(default=1, verbose_name='Частота (F)')
    criticality = models.FloatField(default=0.5, verbose_name='Критичность (C)')
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='monitored', verbose_name='Статус'
    )
    description = models.TextField(blank=True, verbose_name='Описание')

    class Meta:
        verbose_name = 'Политика команды'
        verbose_name_plural = 'Политики команд'
        ordering = ['command']

    def __str__(self):
        return self.command


class EventLog(models.Model):
    EVENT_TYPES = [
        ('auth_success', 'Успешная аутентификация'),
        ('auth_fail', 'Ошибка аутентификации'),
        ('cmd_allowed', 'Команда разрешена'),
        ('cmd_blocked', 'Команда заблокирована'),
        ('cmd_monitored', 'Команда под мониторингом'),
        ('integrity_ok', 'Целостность в норме'),
        ('integrity_fail', 'Нарушение целостности'),
        ('alert_created', 'Создано оповещение'),
        ('policy_change', 'Изменение политики'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True, verbose_name='Время')
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES, verbose_name='Тип события')
    username = models.CharField(max_length=150, blank=True, verbose_name='Пользователь')
    ip_address = models.GenericIPAddressField(null=True, blank=True, verbose_name='IP-адрес')
    command = models.CharField(max_length=255, blank=True, verbose_name='Команда')
    details = models.JSONField(default=dict, verbose_name='Детали')
    prev_hash = models.CharField(max_length=64, blank=True, verbose_name='Хеш предыдущей записи')
    entry_hash = models.CharField(max_length=64, blank=True, verbose_name='Хеш записи')

    class Meta:
        verbose_name = 'Событие'
        verbose_name_plural = 'Журнал событий'
        ordering = ['-timestamp']

    def __str__(self):
        return f'[{self.timestamp}] {self.get_event_type_display()} — {self.username}'

    def verify_hash(self):
        payload = {
            'event_type': self.event_type,
            'username': self.username,
            'ip_address': str(self.ip_address) if self.ip_address else '',
            'command': self.command,
            'details': self.details,
            'timestamp': self.timestamp.isoformat() if self.timestamp else '',
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str) + self.prev_hash
        return hashlib.sha256(raw.encode('utf-8')).hexdigest() == self.entry_hash


class IntegrityRecord(models.Model):
    STATUS_CHOICES = [
        ('ok', 'В норме'),
        ('fail', 'Нарушение'),
        ('unknown', 'Не проверено'),
    ]
    component = models.CharField(max_length=200, unique=True, verbose_name='Компонент')
    description = models.TextField(blank=True, verbose_name='Описание')
    reference_hash = models.CharField(max_length=64, verbose_name='Эталонный хеш (SHA-256)')
    current_hash = models.CharField(max_length=64, blank=True, verbose_name='Текущий хеш')
    last_checked = models.DateTimeField(null=True, blank=True, verbose_name='Последняя проверка')
    last_status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='unknown', verbose_name='Статус'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Запись целостности'
        verbose_name_plural = 'Контроль целостности'
        ordering = ['component']

    def __str__(self):
        return self.component


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ('info', 'Информация'),
        ('warning', 'Предупреждение'),
        ('critical', 'Критическое'),
    ]
    timestamp = models.DateTimeField(auto_now_add=True, verbose_name='Время')
    severity = models.CharField(
        max_length=20, choices=SEVERITY_CHOICES, default='info', verbose_name='Уровень'
    )
    title = models.CharField(max_length=200, verbose_name='Заголовок')
    message = models.TextField(verbose_name='Сообщение')
    is_read = models.BooleanField(default=False, verbose_name='Прочитано')
    dismissed_at = models.DateTimeField(null=True, blank=True, verbose_name='Время закрытия')
    dismissed_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='dismissed_alerts', verbose_name='Закрыто'
    )

    class Meta:
        verbose_name = 'Оповещение'
        verbose_name_plural = 'Оповещения'
        ordering = ['-timestamp']

    def __str__(self):
        return f'[{self.severity.upper()}] {self.title}'

    @property
    def is_dismissed(self):
        return self.dismissed_at is not None
