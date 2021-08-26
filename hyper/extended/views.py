from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

# Create your views here.

class ExtendedView(LoginRequiredMixin, TemplateView):
    pass

extended_dragula_view = ExtendedView.as_view(template_name="extended/dragula.html")
extended_range_slider_view = ExtendedView.as_view(template_name="extended/range-slider.html")
extended_ratings_view = ExtendedView.as_view(template_name="extended/ratings.html")
extended_scrollbar_view = ExtendedView.as_view(template_name="extended/scrollbar.html")
extended_scrollspy_view = ExtendedView.as_view(template_name="extended/scrollspy.html")
extended_treeview_view = ExtendedView.as_view(template_name="extended/treeview.html")