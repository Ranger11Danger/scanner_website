from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from django.views import defaults as default_views
from django.views.generic import TemplateView

urlpatterns = [
    path(
        "about/", TemplateView.as_view(template_name="pages/about.html"), name="about"
    ),
    # Django Admin, use {% url 'admin:index' %}
    path(settings.ADMIN_URL, admin.site.urls),
    # User management
    path("apps/", include("hyper.apps.urls", namespace="apps")),
    path("pages/", include("hyper.pages.urls", namespace="pages")),
    path("layouts/", include("hyper.layouts.urls", namespace="layouts")),
    path("ui/", include("hyper.ui.urls", namespace="ui")),
    path("extended/", include("hyper.extended.urls", namespace="extended")),
    path("icons/", include("hyper.icons.urls", namespace="icons")),
    path("form/", include("hyper.form.urls", namespace="form")),
    path("charts/", include("hyper.charts.urls", namespace="charts")),
    path("tables/", include("hyper.tables.urls", namespace="tables")),
    path("maps/", include("hyper.maps.urls", namespace="maps")),
    path("users/", include("hyper.users.urls", namespace="users")),
    path("accounts/", include("allauth.urls")),
    path("dashboard/", include("hyper.dashboard.urls", namespace="dashboard")),
    path("", include("hyper.dashboard.urls", namespace="dashboard")),
    path('celery-progress/', include('celery_progress.urls'))
    # Your stuff: custom urls includes go here
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


if settings.DEBUG:
    # This allows the error pages to be debugged during development, just visit
    # these url in browser to see how these error pages look like.
    urlpatterns += [
        path(
            "400/",
            default_views.bad_request,
            kwargs={"exception": Exception("Bad Request!")},
        ),
        path(
            "403/",
            default_views.permission_denied,
            kwargs={"exception": Exception("Permission Denied")},
        ),
        path(
            "404/",
            default_views.page_not_found,
            kwargs={"exception": Exception("Page not Found")},
        ),
        path("500/", default_views.server_error),
    ]
    if "debug_toolbar" in settings.INSTALLED_APPS:
        import debug_toolbar

        urlpatterns = [path("__debug__/", include(debug_toolbar.urls))] + urlpatterns
