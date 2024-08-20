from django.urls import path

from rest_framework import routers

from .views import AuthViewSet, RegisterView, LoginView

router = routers.DefaultRouter(trailing_slash=False)
router.register('api/accounts', AuthViewSet, basename='users')

urlpatterns = [
    path('api/accounts/', RegisterView.as_view(), name='register'),
    path('api/login/', LoginView.as_view(), name='login'),
    # path('', FrontendAppView.as_view(), name='home'),
]

urlpatterns = router.urls