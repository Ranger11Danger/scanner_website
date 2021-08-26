from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic.base import TemplateView


class layoutsView(LoginRequiredMixin, TemplateView):
    pass

layouts_horizontal_view = layoutsView.as_view(template_name = "layouts/horizontal.html")
layouts_detached_view = layoutsView.as_view(template_name = "layouts/detached.html")