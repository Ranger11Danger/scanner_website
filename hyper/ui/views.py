from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

# Create your views here.

class UiView(LoginRequiredMixin, TemplateView):
    pass


ui_accordions_view = UiView.as_view(template_name="ui/accordions.html")
ui_alerts_view = UiView.as_view(template_name="ui/alerts.html")
ui_avatars_view = UiView.as_view(template_name="ui/avatars.html")
ui_badges_view = UiView.as_view(template_name="ui/badges.html")
ui_breadcrumb_view = UiView.as_view(template_name="ui/breadcrumb.html")
ui_buttons_view = UiView.as_view(template_name="ui/buttons.html")
ui_cards_view = UiView.as_view(template_name="ui/cards.html")
ui_carousel_view = UiView.as_view(template_name="ui/carousel.html")
ui_dropdowns_view = UiView.as_view(template_name="ui/dropdowns.html")
ui_embed_video_view = UiView.as_view(template_name="ui/embed-video.html")
ui_grid_view = UiView.as_view(template_name="ui/grid.html")
ui_list_group_view = UiView.as_view(template_name="ui/list-group.html")
ui_modals_view = UiView.as_view(template_name="ui/modals.html")
ui_notifications_view = UiView.as_view(template_name="ui/notifications.html")
ui_offcanvas_view = UiView.as_view(template_name="ui/offcanvas.html")
ui_pagination_view = UiView.as_view(template_name="ui/pagination.html")
ui_popovers_view = UiView.as_view(template_name="ui/popovers.html")
ui_progress_view = UiView.as_view(template_name="ui/progress.html")
ui_ribbons_view = UiView.as_view(template_name="ui/ribbons.html")
ui_spinners_view = UiView.as_view(template_name="ui/spinners.html")
ui_tabs_view = UiView.as_view(template_name="ui/tabs.html")
ui_tooltips_view = UiView.as_view(template_name="ui/tooltips.html")
ui_typography_view = UiView.as_view(template_name="ui/typography.html")
