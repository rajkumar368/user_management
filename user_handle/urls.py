from django.urls import path
from .views import UserCreate,UserList

urlpatterns = [
    path('user_creation', UserCreate.as_view(),name="user_creation"),
    path('user_list', UserList.as_view(),name="user_list")
    
]