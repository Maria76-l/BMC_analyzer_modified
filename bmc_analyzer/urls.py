from django.urls import path
from django.http import HttpResponse
from django.contrib.auth.views import LoginView, LogoutView
from . import views


def health(request):
    return HttpResponse('ok', content_type='text/plain')


urlpatterns = [
    path('health/', health, name='health'),
    path('', views.index, name='index'),
    path('api/security-status/', views.security_status, name='security_status'),
    path('login/', LoginView.as_view(template_name='bmc_analyzer/login.html'), name='login'),
    path('logout/', LogoutView.as_view(next_page='/login/', http_method_names=['get', 'post']), name='logout'),
]
