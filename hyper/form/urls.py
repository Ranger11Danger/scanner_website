from django.urls import path

from .views import (
form_advanced_view,
form_editors_view,
form_elements_view,
form_fileuploads_view,
form_validation_view,
form_wizard_view,

)

app_name = "form"
urlpatterns = [
    path("advanced", view=form_advanced_view,name="advanced"),
    path("editors", view=form_editors_view, name="editors"),
    path("elements", view=form_elements_view, name="elements"),
    path("fileuploads", view=form_fileuploads_view, name="fileuploads"),
    path("validation", view=form_validation_view, name="validation"),
    path("wizard", view=form_wizard_view, name="wizard"),
   
]
