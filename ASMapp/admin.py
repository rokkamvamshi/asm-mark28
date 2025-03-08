from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User
from .models import ScanResult
from .models import NucleiResult

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ['username', 'email', 'is_staff', 'is_active']
    list_filter = ['is_staff', 'is_active']
    search_fields = ['username', 'email']
    ordering = ['username']
    fieldsets = UserAdmin.fieldsets  # Include the default fieldsets
    add_fieldsets = UserAdmin.add_fieldsets  # Include the default add fieldsets

class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('user', 'target', 'created_at')  # Display these fields in the list view
    search_fields = ('target', 'user__username')  # Allow searching by target and username
    list_filter = ('created_at', 'user')  # Add filters for created_at and user

admin.site.register(ScanResult, ScanResultAdmin)  # Register the model with the custom admin


admin.site.register(User, CustomUserAdmin)


admin.site.register(NucleiResult)