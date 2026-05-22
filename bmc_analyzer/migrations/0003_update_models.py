import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bmc_analyzer', '0002_delete_eventlog'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Add fields to CommandPolicy
        migrations.AddField(
            model_name='commandpolicy',
            name='status',
            field=models.CharField(
                choices=[('allowed', 'Разрешено'), ('blocked', 'Заблокировано'), ('monitored', 'Мониторинг')],
                default='monitored', max_length=20, verbose_name='Статус'
            ),
        ),
        migrations.AddField(
            model_name='commandpolicy',
            name='description',
            field=models.TextField(blank=True, verbose_name='Описание'),
        ),
        # Create new EventLog with hash chaining
        migrations.CreateModel(
            name='EventLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True, verbose_name='Время')),
                ('event_type', models.CharField(
                    choices=[
                        ('auth_success', 'Успешная аутентификация'),
                        ('auth_fail', 'Ошибка аутентификации'),
                        ('cmd_allowed', 'Команда разрешена'),
                        ('cmd_blocked', 'Команда заблокирована'),
                        ('cmd_monitored', 'Команда под мониторингом'),
                        ('integrity_ok', 'Целостность в норме'),
                        ('integrity_fail', 'Нарушение целостности'),
                        ('alert_created', 'Создано оповещение'),
                        ('policy_change', 'Изменение политики'),
                    ],
                    max_length=30, verbose_name='Тип события'
                )),
                ('username', models.CharField(blank=True, max_length=150, verbose_name='Пользователь')),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True, verbose_name='IP-адрес')),
                ('command', models.CharField(blank=True, max_length=255, verbose_name='Команда')),
                ('details', models.JSONField(default=dict, verbose_name='Детали')),
                ('prev_hash', models.CharField(blank=True, max_length=64, verbose_name='Хеш предыдущей записи')),
                ('entry_hash', models.CharField(blank=True, max_length=64, verbose_name='Хеш записи')),
            ],
            options={'verbose_name': 'Событие', 'verbose_name_plural': 'Журнал событий', 'ordering': ['-timestamp']},
        ),
        # Create IntegrityRecord
        migrations.CreateModel(
            name='IntegrityRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('component', models.CharField(max_length=200, unique=True, verbose_name='Компонент')),
                ('description', models.TextField(blank=True, verbose_name='Описание')),
                ('reference_hash', models.CharField(max_length=64, verbose_name='Эталонный хеш (SHA-256)')),
                ('current_hash', models.CharField(blank=True, max_length=64, verbose_name='Текущий хеш')),
                ('last_checked', models.DateTimeField(blank=True, null=True, verbose_name='Последняя проверка')),
                ('last_status', models.CharField(
                    choices=[('ok', 'В норме'), ('fail', 'Нарушение'), ('unknown', 'Не проверено')],
                    default='unknown', max_length=20, verbose_name='Статус'
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={'verbose_name': 'Запись целостности', 'verbose_name_plural': 'Контроль целостности', 'ordering': ['component']},
        ),
        # Create Alert
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True, verbose_name='Время')),
                ('severity', models.CharField(
                    choices=[('info', 'Информация'), ('warning', 'Предупреждение'), ('critical', 'Критическое')],
                    default='info', max_length=20, verbose_name='Уровень'
                )),
                ('title', models.CharField(max_length=200, verbose_name='Заголовок')),
                ('message', models.TextField(verbose_name='Сообщение')),
                ('is_read', models.BooleanField(default=False, verbose_name='Прочитано')),
                ('dismissed_at', models.DateTimeField(blank=True, null=True, verbose_name='Время закрытия')),
                ('dismissed_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='dismissed_alerts',
                    to=settings.AUTH_USER_MODEL,
                    verbose_name='Закрыто'
                )),
            ],
            options={'verbose_name': 'Оповещение', 'verbose_name_plural': 'Оповещения', 'ordering': ['-timestamp']},
        ),
    ]
