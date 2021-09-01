from django.urls import path
from django.conf.urls import url
from .views import (dashboard_main_view,
                    dashboard_scan_details,
                    dashboard_cve_details,
                    dashboard_scan_view,
                    dashboard_celery_view,
                    )

app_name = "dashboard"
urlpatterns = [
    path("", view=dashboard_main_view, name="index"),
    url(r'^scan/(?P<slug>[\w-]+)/(?P<cveid>[\w-]+)/$', view=dashboard_cve_details, name="cve details"),
    url(r'^scan/(?P<slug>[\w-]+)/$', view=dashboard_scan_details, name="scan details"),
    url(r'^scan/$', view=dashboard_scan_view, name="scan"),
    url(r'^celery/', view=dashboard_celery_view, name="celery"),
    
]
