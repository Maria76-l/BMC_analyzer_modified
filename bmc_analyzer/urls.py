from django.urls import path
from django.http import HttpResponse
from django.contrib.auth.views import LoginView, LogoutView
from . import views


def health(request):
    return HttpResponse('ok', content_type='text/plain')


urlpatterns = [
    path('health/', health, name='health'),
    path('', views.index, name='index'),
    path('logs/', views.logs_view, name='logs'),
    path('alerts/', views.alerts_view, name='alerts'),
    path('alerts/dismiss/<int:alert_id>/', views.dismiss_alert, name='dismiss_alert'),
    path('alerts/dismiss-all/', views.dismiss_all_alerts, name='dismiss_all_alerts'),
    path('policies/', views.policies_view, name='policies'),
    path('policies/simulate/', views.simulate_command_api, name='simulate_command'),
    path('policies/add/', views.add_policy, name='add_policy'),
    path('policies/delete/<int:policy_id>/', views.delete_policy, name='delete_policy'),
    path('api/security-status/', views.security_status, name='security_status'),
    path('login/', LoginView.as_view(template_name='bmc_analyzer/login.html'), name='login'),
    path('logout/', LogoutView.as_view(next_page='/login/', http_method_names=['get', 'post']), name='logout'),
]
