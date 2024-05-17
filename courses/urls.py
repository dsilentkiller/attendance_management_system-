from django.contrib import admin
from django.urls import path
from courses import views
urlpatterns = [
    path('subjects/', views.SubjectsList.as_view(), name=('list')),
    path('subjects/<int:pk>/', views.SubjectsDetail.as_view(), name=('detail')),
]
