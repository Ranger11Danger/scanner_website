from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
from django.views.generic import TemplateView
from .forms import ScanForm, RenameScanForm
from hyper.utils.general import list_scans, add_scan,select_scans,clear_scans,select_slug,get_db_data,convert_scan_to_model,clear_ports,num_cves,get_cve,clense_ips
from .tasks import go_to_sleep
from django.shortcuts import redirect


User = get_user_model()
class LoginRequiredView(LoginRequiredMixin, TemplateView):
    pass


class DashboardMainView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/main.html"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        scans = select_scans(self.request.user.id)
        context['cve_nums'] = num_cves(self.request.user.id)
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
class CveDetailsView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/cve_details.html"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        scan_id = self.kwargs['slug']
        cve_id = self.kwargs['cveid']
        context['cve'] = get_cve(scan_id,cve_id,self.request.user.id)
        return context

class ScanView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/scan.html"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['scan_form'] = ScanForm()
        return context
    def post(self, request, **kwargs):
        context = self.get_context_data(**kwargs)
        form = ScanForm(request.POST)
        if form.is_valid():
            context['name'] = form.cleaned_data['name']
            context['address'] = clense_ips(form.cleaned_data['address'])
            context['task_id'] = convert_scan_to_model(form.cleaned_data['name'])

        return self.render_to_response(context)

class ScanManageView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/scan-manage.html"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['slug'] = self.kwargs['slug']
        context['rename_form'] = RenameScanForm()
        return context

    def post(self, request, **kwargs):
        context = self.get_context_data(**kwargs)
        form = RenameScanForm(request.POST)
        if form.is_valid():
            context['new_name'] = form.cleaned_data['name']
        if request.POST.get('delete'):
            clear_ports()
            return redirect('/')
        return self.render_to_response(context)

dashboard_manage_scan_view = ScanManageView.as_view()
dashboard_scan_view = ScanView.as_view()
dashboard_cve_details = CveDetailsView.as_view()
dashboard_main_view = DashboardMainView.as_view()
dashboard_scan_details = ScanDetailsView.as_view()

