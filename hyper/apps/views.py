import json
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.views import View
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404


from hyper.apps.models import Event
from hyper.apps.forms import EventForm



class EventListView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        events = Event.objects.all()
        events_dict = []
        for event in events:
            events_dict.append(event.to_dict())
        return HttpResponse(json.dumps(events_dict), content_type='application/json')

class EventCreateView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        form = EventForm(data=request.POST)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            save_data = {}
            save_data["title"] = cleaned_data.get("title")
            save_data["category"] = cleaned_data.get("className")
            save_data["start_date"] = cleaned_data.get("start")
            if cleaned_data.get("allDay", None):
                save_data["all_day"] = cleaned_data.get("allDay")
            if cleaned_data.get("end", None):
                save_data["end_date"] = cleaned_data.get("end")
            event = Event.objects.create(**save_data)
            return HttpResponse(json.dumps(event.to_dict()), content_type='application/json')
        return HttpResponseBadRequest(json.dumps(form.errors), content_type='application/json')

class EventUpdateView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        pk = kwargs.get("pk", None)
        obj = get_object_or_404(Event, id=pk)
        form = EventForm(data=request.POST)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            obj.title = cleaned_data.get("title")
            obj.category = cleaned_data.get("className")
            obj.start_date = cleaned_data.get("start")
            obj.all_day = cleaned_data.get("allDay", None)
            obj.end_date = cleaned_data.get("end", None)
            obj.save()
            return HttpResponse(json.dumps(obj.to_dict()), content_type='application/json')
        return HttpResponseBadRequest(json.dumps(form.errors), content_type='application/json')

class EventDeleteView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        pk = kwargs.get("pk", None)
        obj = get_object_or_404(Event, id=pk)
        obj.delete()
        return HttpResponse(
            json.dumps({"message" : "The event has been removed successfully."}), 
            content_type='application/json'
            )        


class AppsView(LoginRequiredMixin, TemplateView):
    pass

# calendar
apps_calendar_calendar_view = AppsView.as_view(template_name="apps/calendar/calendar.html")


class AppsView(LoginRequiredMixin, TemplateView):
    pass

#chat
apps_chat_chat_view = AppsView.as_view(template_name="apps/chat/chat.html")

# email
apps_email_inbox_view = AppsView.as_view(template_name="apps/email/inbox.html")
apps_email_read_view = AppsView.as_view(template_name="apps/email/read.html")

# file manager
apps_file_manager_view = AppsView.as_view(template_name="apps/file/manager.html")

# projects
apps_projects_add_view = AppsView.as_view(template_name="apps/projects/add.html")
apps_projects_details_view = AppsView.as_view(template_name="apps/projects/details.html")
apps_projects_gantt_view = AppsView.as_view(template_name="apps/projects/gantt.html")
apps_projects_list_view = AppsView.as_view(template_name="apps/projects/list.html")

# social
apps_social_feed_view = AppsView.as_view(template_name="apps/social/feed.html")

# tasks
apps_tasks_details_view = AppsView.as_view(template_name="apps/tasks/details.html")
apps_tasks_kanban_view = AppsView.as_view(template_name="apps/tasks/kanban.html")
apps_tasks_tasks_view = AppsView.as_view(template_name="apps/tasks/tasks.html")
