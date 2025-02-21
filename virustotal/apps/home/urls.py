

from django.urls import path, re_path
from apps.home import views

urlpatterns = [
    path('ip_search/', views.get_ip_threat_intel, name='get_ip_threat_intel'),
    path('notification/', views.notification_view, name='notification'),
    path('', views.index, name='home'),
    path('analyze_url/', views.analyze_url, name='analyze_url'),
    path('upload/analyze/', views.upload_and_analyze, name='upload_and_analyze'),
    path('api/chat/', views.chatbot, name='chat_view'),
    path("upload/",views.file_upload,name="upload"),
    # path("upload/",views.upload,name="upload"),
    re_path(r'^.*\.*', views.pages, name='pages'),
]
