from django.urls import path

from .views import (
tables_datatable_view,
tables_basic_view,
)

app_name = "tables"
urlpatterns = [
    path("datatable", view=tables_datatable_view,name="datatable"),
    path("basic", view=tables_basic_view, name="basic"),
]
