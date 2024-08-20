from django.urls import include, path
from .views import RegisterView, LoginView

urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/login/', LoginView.as_view(), name='login'),
    # path('', FrontendAppView.as_view(), name='home'),
]