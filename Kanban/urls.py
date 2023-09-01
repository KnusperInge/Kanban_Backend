
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from Kanban_App.views import Taskview_Set, login_View, UserViewSet, ChangePasswordView, RegisterView

router = routers.DefaultRouter()

router.register(r'tasks', Taskview_Set, basename='tasks')
router.register(r'users', UserViewSet, basename='users')
urlpatterns = [
    path('', include(router.urls)),
    path('login/', login_View.as_view()),
    path('register/', RegisterView.as_view()),
    path('change_password/<int:pk>/', ChangePasswordView.as_view(),
         name='auth_change_password'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('admin/', admin.site.urls),
]
