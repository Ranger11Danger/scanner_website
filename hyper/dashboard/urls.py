from django.urls import path
from django.conf.urls import url
from .views import (dashboard_main_view,
                    dashboard_scan_details,
                    dashboard_cve_details,
                    dashboard_scan_view,
                    dashboard_manage_scan_view,
                    dashboard_address_view,
                    address_details_view,
                    address_cve_details_view
                    )

app_name = "dashboard"
urlpatterns = [
    path("", view=dashboard_main_view, name="index"),
    path("addresses", view=dashboard_address_view, name="address view"),
    path('addresses/<slug:slug>/', view=address_details_view, name="address details"),
    path('addresses/<slug:slug>/<slug:cveid>/', view=address_cve_details_view, name="address cve details"),
    url(r'^scan/(?P<slug>[\w-]+)/manage/$', view=dashboard_manage_scan_view, name="manage scan"),
    url(r'^scan/(?P<slug>[\w-]+)/(?P<cveid>[\w-]+)/$', view=dashboard_cve_details, name="cve details"),
    url(r'^scan/(?P<slug>[\w-]+)/$', view=dashboard_scan_details, name="scan details"),
    url(r'^scan/$', view=dashboard_scan_view, name="scan"),
]
