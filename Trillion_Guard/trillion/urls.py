from django.contrib import admin
from django.urls import path
from trillion import views
from django.contrib.auth import views as auth_views
from django.views.static import serve
from django.urls import re_path
from django.conf import settings
app_name = 'trillion'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.search, name='search'), # ok
    path('board/', views.board_VIEW.as_view(), name='board'),
    path('chart/',  views.chart_VIEW.as_view(), name='chart'),
    path('detail/', views.detail, name='detail'),
    path('append/', views.append, name='append'),
    path('contact/', views.contact, name='contact'),
    path('register/', views.register, name='register'),
    path('login/', auth_views.LoginView.as_view(), name="login"),
    path('logout/', auth_views.LogoutView.as_view(), name="logout"),

    path('shareInfo/', views.shareInfo_index, name='shareInfo_index'),
    path('shareInfo/<int:pk>/',views.shareInfo_show, name = 'shareInfo_show'),
    path('shareInfo/new/',views.shareInfo_new, name = 'shareInfo_new'),
    path('shareInfo/create/', views.shareInfo_create, name = 'shareInfo_create'),
    path('shareInfo/<int:pk>/delete/',views.shareInfo_delete, name = 'shareInfo_delete'),
    
    re_path(r'^media/(?P<path>.*)$', serve, {'document_root':settings.MEDIA_ROOT})
]