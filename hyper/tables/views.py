from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

# Create your views here.

class TablesView(LoginRequiredMixin, TemplateView):
    pass

tables_datatable_view = TablesView.as_view(template_name="tables/datatable.html")
tables_basic_view = TablesView.as_view(template_name="tables/basic.html")
