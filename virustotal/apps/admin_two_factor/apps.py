from django.apps import AppConfig


class TwoStepVerificationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.admin_two_factor'  # Doğru modül yolu
    verbose_name = 'Two Factor Authentication'  # Daha açıklayıcı bir ad
