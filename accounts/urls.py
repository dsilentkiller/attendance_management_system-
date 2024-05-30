from django.contrib import admin
from django.urls import path
from accounts import views
urlpatterns = [
    path('register', views.RegisterView.as_view(), name=('register')),
    path('login', views.LoginView.as_view(), name=('login')),
    path('change_password', views.ChangePasswordView.as_view(),
         name='change_password'),
    path('reset-password/', views.PasswordResetRequestView.as_view(),
         name='reset-password'),
    path('reset-password-confirm/', views.PasswordResetConfirmView.as_view(),
         name='reset-password-confirm'),
]
