import json
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
from django.views.generic import TemplateView
import sqlite3

from hyper.utils.general import list_scans, add_scan,select_scans,clear_scans,select_slug,get_db_data,convert_scan_to_model,clear_ports



User = get_user_model()

class LoginRequiredView(LoginRequiredMixin, TemplateView):
    pass


class DashboardMainView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/main.html"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        scans = select_scans(self.request.user.id)
        context['scans'] = scans
        context['scan_num'] = len(scans)
        return context


class ScanDetailsView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/scan_details.html"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['slug'] = self.kwargs['slug']
        selected_scan = select_slug(self.kwargs['slug'],self.request.user.id)
        context['scan'] = selected_scan
        if len(selected_scan) >= 1:
            context['data'] = get_db_data(self.kwargs['slug'], self.request.user.id)
        return context

dashboard_main_view = DashboardMainView.as_view()
dashboard_scan_details = ScanDetailsView.as_view()

