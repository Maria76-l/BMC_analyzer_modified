from django.contrib import admin
from .models import CommandPolicy

@admin.register(CommandPolicy)
class CommandPolicyAdmin(admin.ModelAdmin):
    list_display = ('command', 'frequency', 'criticality')
    list_editable = ('frequency', 'criticality')