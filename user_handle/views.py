from django.shortcuts import render
from django.views.generic.edit import CreateView
from authentication.models import User
from django.views.generic.list import ListView
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib.auth.mixins import LoginRequiredMixin

# admin group creating and assigning to both view pending
class UserCreate(CreateView,LoginRequiredMixin,PermissionRequiredMixin):
    model = User
    fields = ['email', 'username', 'password','is_staff', 'is_superuser']
    permission_required = 'authentication.add_User'
    template_name = "user_form.html"

class UserList(ListView,LoginRequiredMixin,PermissionRequiredMixin):
    model = User
    queryset = User.objects.all()
    permission_required = 'authentication.view_User'
    context_object_name = "users_list"
    template_name = "user_list.html"

