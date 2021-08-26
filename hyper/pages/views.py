from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

# Create your views here.

class PagesView(LoginRequiredMixin, TemplateView):
    pass

pages_404_alt_view = PagesView.as_view(template_name="pages/404-alt.html")
pages_404_view = PagesView.as_view(template_name="pages/404.html")
pages_500_view = PagesView.as_view(template_name="pages/500.html")
pages_confirm_mail_2_view = PagesView.as_view(template_name="pages/confirm-mail-2.html")
pages_confirm_mail_view = PagesView.as_view(template_name="pages/confirm-mail.html")
pages_faq_view = PagesView.as_view(template_name="pages/faq.html")
pages_invoice_view = PagesView.as_view(template_name="pages/invoice.html")
pages_lock_screen_2_view = PagesView.as_view(template_name="pages/lock-screen-2.html")
pages_lock_screen_view = PagesView.as_view(template_name="pages/lock-screen.html")
pages_login_2_view = PagesView.as_view(template_name="pages/login-2.html")
pages_login_view = PagesView.as_view(template_name="pages/login.html")
pages_logout_2_view = PagesView.as_view(template_name="pages/logout-2.html")
pages_logout_view = PagesView.as_view(template_name="pages/logout.html")
pages_maintenance_view = PagesView.as_view(template_name="pages/maintenance.html")
pages_preloader_view = PagesView.as_view(template_name="pages/preloader.html")
pages_pricing_view = PagesView.as_view(template_name="pages/pricing.html")
pages_profile_2_view = PagesView.as_view(template_name="pages/profile-2.html")
pages_profile_view = PagesView.as_view(template_name="pages/profile.html")
pages_recoverpw_2_view = PagesView.as_view(template_name="pages/recoverpw-2.html")
pages_recoverpw_view = PagesView.as_view(template_name="pages/recoverpw.html")
pages_register_2_view = PagesView.as_view(template_name="pages/register-2.html")
pages_register_view = PagesView.as_view(template_name="pages/register.html")
pages_starter_view = PagesView.as_view(template_name="pages/starter.html")
pages_timeline_view = PagesView.as_view(template_name="pages/timeline.html")
