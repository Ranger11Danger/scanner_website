from django.urls import path

from .views import (
icons_dripicons_view ,
icons_mdi_view ,
icons_unicons_view ,

)

app_name = "icons"
urlpatterns = [
    path("dripicons", view=icons_dripicons_view,name="dripicons"),
    path("mdi", view=icons_mdi_view,name="mdi"),
    path("unicons", view=icons_unicons_view,name="unicons"),
   
]
