from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

# Create your views here.



class FormView(LoginRequiredMixin, TemplateView):
    pass

form_advanced_view = FormView.as_view(template_name="form/advanced.html")
form_editors_view = FormView.as_view(template_name="form/editors.html")
form_elements_view = FormView.as_view(template_name="form/elements.html")
form_fileuploads_view = FormView.as_view(template_name="form/fileuploads.html")
form_validation_view = FormView.as_view(template_name="form/validation.html")
form_wizard_view = FormView.as_view(template_name="form/wizard.html")

