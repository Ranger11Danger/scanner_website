from django.urls import path

from .views import (layouts_horizontal_view, layouts_detached_view)

app_name = "layouts"
urlpatterns = [
    path("horizontal", view=layouts_horizontal_view, name="horizontal"),
    path("detached", view=layouts_detached_view, name="detached"),
]
