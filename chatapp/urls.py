from django.urls import path
from . import views
# app_name = 'chatapp'

urlpatterns = [
    path('register/', views.RegistrationView.as_view(), name="register"),
    path('activate/<token>', views.activate, name='activate'),
    path('login/', views.LoginView.as_view(), name="login"),
    path('logout/', views.LogoutView.as_view(), name="logout"),
    # path('signin/', views.LoginView.as_view(), name="logout"),
    path('reset/', views.ForgotPassword.as_view(), name="reset"),
    path('reset_password/<token>', views.ResetPassword.as_view(), name="reset_password"),
]
