from django.urls import include, path

from rest_framework import routers

from .views import AuthViewSet, LoginView

router = routers.DefaultRouter(trailing_slash=False)

authentication_routes = router.register("api/accounts", AuthViewSet, basename='auth')

urlpatterns = [
    # path('api/accounts/', RegisterView.as_view(), name='register'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api-auth/', include('rest_framework.urls')),
    # path('', FrontendAppView.as_view(), name='home'),
]

urlpatterns += router.urls