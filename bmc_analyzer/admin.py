from django.contrib import admin
from .models import CommandPolicy, EventLog, IntegrityRecord, Alert


@admin.register(CommandPolicy)
class CommandPolicyAdmin(admin.ModelAdmin):
    list_display = ('command', 'status', 'frequency', 'criticality')
    list_editable = ('status', 'frequency', 'criticality')
    list_filter = ('status',)
    search_fields = ('command',)


@admin.register(EventLog)
class EventLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'event_type', 'username', 'ip_address', 'command')
    list_filter = ('event_type',)
    search_fields = ('username', 'command', 'ip_address')
    readonly_fields = ('timestamp', 'prev_hash', 'entry_hash', 'details')
    ordering = ('-timestamp',)

    def has_delete_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request):
        return False


@admin.register(IntegrityRecord)
class IntegrityRecordAdmin(admin.ModelAdmin):
    list_display = ('component', 'last_status', 'last_checked', 'reference_hash')
    list_filter = ('last_status',)
    search_fields = ('component',)
    readonly_fields = ('last_checked', 'last_status', 'created_at', 'updated_at')


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'severity', 'title', 'is_read', 'dismissed_at')
    list_filter = ('severity', 'is_read')
    search_fields = ('title', 'message')
    readonly_fields = ('timestamp', 'dismissed_at', 'dismissed_by')
