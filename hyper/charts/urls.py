from django.urls import path

from .views import (
charts_sbrite_view,
charts_chartjs_view,
charts_sparkline_view,
charts_apex_area_view,
charts_apex_bar_view,
charts_apex_bubble_view,
charts_apex_candlestick_view,
charts_apex_column_view,
charts_apex_heatmap_view,
charts_apex_line_view,
charts_apex_mixed_view,
charts_apex_pie_view,
charts_apex_radar_view,
charts_apex_radialbar_view,
charts_apex_scatter_view,
charts_apex_sparklines_view,
)

app_name = "charts"
urlpatterns = [
    path("sbrite", view=charts_sbrite_view, name="sbrite"),
    path("chartjs", view=charts_chartjs_view, name="chartjs"),
    path("sparkline", view=charts_sparkline_view, name="sparkline"),
    path("apex/area", view=charts_apex_area_view, name="apex.area"),
    path("apex/bar", view=charts_apex_bar_view, name="apex.bar"),
    path("apex/bubble", view=charts_apex_bubble_view, name="apex.bubble"),
    path("apex/candlestick", view=charts_apex_candlestick_view, name="apex.candlestick"),
    path("apex/column", view=charts_apex_column_view, name="apex.column"),
    path("apex/heatmap", view=charts_apex_heatmap_view, name="apex.heatmap"),
    path("apex/line", view=charts_apex_line_view, name="apex.line"),
    path("apex/mixed", view=charts_apex_mixed_view, name="apex.mixed"),
    path("apex/pie", view=charts_apex_pie_view, name="apex.pie"),
    path("apex/radar", view=charts_apex_radar_view, name="apex.radar"),
    path("apex/radialbar", view=charts_apex_radialbar_view, name="apex.radialbar"),
    path("apex/scatter", view=charts_apex_scatter_view, name="apex.scatter"),
    path("apex/sparklines", view=charts_apex_sparklines_view, name="apex.sparklines"),
   
]
