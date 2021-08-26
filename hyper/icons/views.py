from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

# Create your views here.


class IconsView(LoginRequiredMixin, TemplateView):
    pass

icons_dripicons_view = IconsView.as_view(template_name="icons/dripicons.html")
icons_mdi_view = IconsView.as_view(template_name="icons/mdi.html")
icons_unicons_view = IconsView.as_view(template_name="icons/unicons.html")
