
from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),                        # Log Reg page
    url(r'^register/', views.register),             # Reg route
    url(r'^login/', views.user_login),              # Login route
    url(r'^log_out/', views.user_logout),           # logout route
    url(r'^remove/(?P<quote_id>\w+)/$', views.remove_favorite),  # remove favorite
    url(r'^add_quote/$$', views.add_quote),         # add new quote
    url(r'^fav_quote/(?P<quote_id>\w+)/$', views.favorite_quote),    # TODO add favorite
    url(r'^quote/(?P<owner_id>\w+)/$', views.user_quotes),      # quote makers page
    url(r'^dashboard/$', views.index),                          # user dashboard
    url(r'^dashboard/(?P<username>\w+)/$', views.dashboard),    # user dashboard

    # url(r'^login/edit', views.edit),
    # /(?P<username>\w+)/$
    # /(?P<username>\w*)/$
    # /(?P<id>\d+)/$
]
