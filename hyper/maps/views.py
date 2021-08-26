from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

# Create your views here.

class MapsView(LoginRequiredMixin, TemplateView):
    pass

maps_google_view = MapsView.as_view(template_name="maps/google.html")
maps_vector_view = MapsView.as_view(template_name="maps/vector.html")
