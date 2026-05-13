"""
URL configuration for cybersec_webapp project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path
from threat_app.views import *

urlpatterns = [
    path("", cover_page, name="home"),
    path("home/", cover_page, name="cover_page"),
    path("login/", login_page, name="login"),
    path("register/", register, name="register"), # Added register path
    path("settings/", settings_page, name="settings"), # Added settings path
    path("dashboard/", dashboard, name="dashboard"),
    path("detect-ajax/", detect_ajax, name="detect_ajax"),
    path("upload-csv/", upload_csv, name="upload_csv"),
    path("upload-csv-async/", upload_csv_async, name="upload_csv_async"),
    path("upload-job-status/<int:job_id>/", upload_job_status, name="upload_job_status"),
    path("history/", history, name="history"),
    path("logout/", logout, name="logout"),
    path("live-stats/", live_stats, name="live_stats"),
    path("api/dashboard-stats/", get_dashboard_stats, name="dashboard_stats"),
    path("start-monitor/", start_live_monitor, name="start_monitor"),
    path("stop-monitor/", stop_live_monitor, name="stop_monitor"),

]

    

