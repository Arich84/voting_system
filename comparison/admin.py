from django.contrib import admin
from .models import Program, Level, ComparisonData
from django.contrib.admin import SimpleListFilter

# Define the custom filter for the 'valid' field
class ValidFilter(SimpleListFilter):
    title = 'Valid Status'  # Title that appears in the admin filter sidebar
    parameter_name = 'valid_status'  # URL parameter for the filter

    # Define the filter options that will appear in the filter sidebar
    def lookups(self, request, model_admin):
        return (
            ('Valid', 'Valid'),   # Option 1: Valid
            ('Invalid', 'Invalid'),  # Option 2: Invalid
        )

    # Define the queryset logic for filtering based on the selected option
    def queryset(self, request, queryset):
        if self.value() == 'Valid':
            return queryset.filter(valid=True)  # Filter for valid entries
        elif self.value() == 'Invalid':
            return queryset.filter(valid=False)  # Filter for invalid entries

@admin.register(Program)
class ProgramAdmin(admin.ModelAdmin):
    list_display = ('name',)

@admin.register(Level)
class LevelAdmin(admin.ModelAdmin):
    list_display = ('name',)

@admin.register(ComparisonData)
class ComparisonDataAdmin(admin.ModelAdmin):
    list_display = ('matriculation_number', 'first_name', 'last_name', 'email', 'program', 'level', 'valid')
    search_fields = ('first_name', 'last_name', 'email')
    list_filter = ('program', 'level', 'valid')
    readonly_fields = ('matriculation_number', 'email')
