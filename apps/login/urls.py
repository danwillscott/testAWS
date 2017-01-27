
from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^register', views.register),
    url(r'^log_in', views.user_login),
    url(r'^logged_in', views.is_logged_in),
    url(r'^log_out', views.user_logout),
    url(r'^login/(?P<username>\w+)/$', views.edit),
    url(r'^login/edit/(?P<username>\w*)/$', views.edit),
]
