from django.urls import path
from django.conf.urls import url
from .views import (dashboard_main_view,
                    dashboard_scan_details
                    )

app_name = "dashboard"
urlpatterns = [
    path("", view=dashboard_main_view, name="index"),
    url(r'^scan/(?P<slug>[\w-]+)/$', view=dashboard_scan_details, name="scan details")
]
