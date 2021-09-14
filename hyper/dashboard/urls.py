from django.urls import path
from django.conf.urls import url
from django.views.generic.base import View
from .views import (dashboard_main_view,
                    dashboard_scan_details,
                    dashboard_cve_details,
                    dashboard_scan_view,
                    dashboard_manage_scan_view,
                    dashboard_address_view,
                    address_details_view,
                    address_cve_details_view,
                    asset_group_view,
                    asset_group_create_view,
                    asset_group_manage_view,
                    asset_group_address_view,
                    dashboard_info_view,
                    dashboard_score_view,
                    asset_group_scan_view,
                    download_view
                    )

app_name = "dashboard"
urlpatterns = [
    path("dashboard/level/<slug:score>/", view=dashboard_score_view, name="dashboard score"),
    path("dashboard/scans", view=dashboard_main_view, name="index"),
    path("", view=dashboard_info_view, name="info"),
    path("addresses", view=dashboard_address_view, name="address view"),
    path('addresses/<slug:slug>/', view=address_details_view, name="address details"),
    path('addresses/<slug:slug>/<slug:cveid>/', view=address_cve_details_view, name="address cve details"),
    path("assets/", view=asset_group_view, name="asset view"),
    path("assets/create", view=asset_group_create_view, name="create asset group"),
    path("assets/manage/<slug:groupid>/", view=asset_group_manage_view, name="manage asset group"),
    path("assets/<slug:groupid>", view=asset_group_address_view, name="group address view"),
    path("assets/<slug:groupid>/scan", view=asset_group_scan_view, name="group scan view"),
    path("download/<slug:downloadtype>/<slug:downloadvalue>", view=download_view, name="download view"),
    url(r'^scan/(?P<slug>[\w-]+)/manage/$', view=dashboard_manage_scan_view, name="manage scan"),
    url(r'^scan/(?P<slug>[\w-]+)/(?P<cveid>[\w-]+)/$', view=dashboard_cve_details, name="cve details"),
    url(r'^scan/(?P<slug>[\w-]+)/$', view=dashboard_scan_details, name="scan details"),
    url(r'^scan/$', view=dashboard_scan_view, name="scan"),
]
