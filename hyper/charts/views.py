from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin

# Create your views here.


class ChartsView(LoginRequiredMixin, TemplateView):
    pass



charts_sbrite_view = ChartsView.as_view(template_name="charts/brite.html")
charts_chartjs_view = ChartsView.as_view(template_name="charts/chartjs.html")
charts_sparkline_view = ChartsView.as_view(template_name="charts/sparkline.html")
charts_apex_area_view = ChartsView.as_view(template_name="charts/apex/area.html")
charts_apex_bar_view = ChartsView.as_view(template_name="charts/apex/bar.html")
charts_apex_bubble_view = ChartsView.as_view(template_name="charts/apex/bubble.html")
charts_apex_candlestick_view = ChartsView.as_view(template_name="charts/apex/candlestick.html")
charts_apex_column_view = ChartsView.as_view(template_name="charts/apex/column.html")
charts_apex_heatmap_view = ChartsView.as_view(template_name="charts/apex/heatmap.html")
charts_apex_line_view = ChartsView.as_view(template_name="charts/apex/line.html")
charts_apex_mixed_view = ChartsView.as_view(template_name="charts/apex/mixed.html")
charts_apex_pie_view = ChartsView.as_view(template_name="charts/apex/pie.html")
charts_apex_radar_view = ChartsView.as_view(template_name="charts/apex/radar.html")
charts_apex_radialbar_view = ChartsView.as_view(template_name="charts/apex/radialbar.html")
charts_apex_scatter_view = ChartsView.as_view(template_name="charts/apex/scatter.html")
charts_apex_sparklines_view = ChartsView.as_view(template_name="charts/apex/sparklines.html")
