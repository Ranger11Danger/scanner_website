!function(s){"use strict";function e(){this.$body=s("body"),this.$modal=s("#event-modal"),this.$calendar=s("#calendar"),this.$formEvent=s("#form-event"),this.$btnNewEvent=s("#btn-new-event"),this.$btnDeleteEvent=s("#btn-delete-event"),this.$btnSaveEvent=s("#btn-save-event"),this.$modalTitle=s("#modal-title"),this.$calendarObj=null,this.$selectedEvent=null,this.$newEventData=null}var t=s("#eventurls").data("list"),o=s("#eventurls").data("add"),l=s("input[name='csrfmiddlewaretoken']").val();e.prototype.onEventResize=function(e){var t=e.event,e={title:t.title,start:moment(t.start).format("YYYY-MM-DD hh:mm:ss"),allDay:t.allDay,className:t.classNames[0],csrfmiddlewaretoken:l};t.end&&(e.end=moment(t.end).format("YYYY-MM-DD hh:mm:ss")),s.ajax({type:"POST",url:"/apps/event/edit/"+t.extendedProps.pk,data:e,success:function(e){},error:function(e){for(const t in e.responseJSON)console.log(t,":",e.responseJSON[t])}})},e.prototype.onEventDrop=function(e){var t=e.event,e={title:t.title,start:moment(t.start).format("YYYY-MM-DD hh:mm:ss"),allDay:t.allDay,className:t.classNames[0],csrfmiddlewaretoken:l};t.end&&(e.end=moment(t.end).format("YYYY-MM-DD hh:mm:ss")),s.ajax({type:"POST",url:"/apps/event/edit/"+t.extendedProps.pk,data:e,success:function(e){},error:function(e){for(const t in e.responseJSON)console.log(t,":",e.responseJSON[t])}})},e.prototype.onEventReceive=function(e){var t=e.event;s.ajax({type:"POST",url:o,data:{title:t.title,start:moment(t.start).format("YYYY-MM-DD hh:mm:ss"),allDay:t.allDay,className:t.classNames[0],csrfmiddlewaretoken:l},success:function(e){t.setExtendedProp("pk",e.pk)},error:function(e){for(const t in e.responseJSON)console.log(t,":",e.responseJSON[t])}})},e.prototype.onEventClick=function(e){this.$formEvent[0].reset(),this.$formEvent.removeClass("was-validated"),this.$newEventData=null,this.$btnDeleteEvent.show(),this.$modalTitle.text("Edit Event"),this.$modal.show(),this.$selectedEvent=e.event,s("#event-title").val(this.$selectedEvent.title),s("#event-category").val(this.$selectedEvent.classNames[0])},e.prototype.onSelect=function(e){this.$formEvent[0].reset(),this.$formEvent.removeClass("was-validated"),this.$selectedEvent=null,this.$newEventData=e,this.$btnDeleteEvent.hide(),this.$modalTitle.text("Add New Event"),this.$modal.show(),this.$calendarObj.unselect()},e.prototype.init=function(){this.$modal=new bootstrap.Modal(document.getElementById("event-modal"),{keyboard:!1});var e=new Date(s.now());new FullCalendar.Draggable(document.getElementById("external-events"),{itemSelector:".external-event",eventData:function(e){return{title:e.innerText,className:s(e).data("class")}}});new Date(s.now()+158e6),new Date(s.now()+338e6),new Date(s.now()+168e6),new Date(s.now()+338e6),new Date(s.now()+4056e5);var a=this;a.$calendarObj=new FullCalendar.Calendar(a.$calendar[0],{slotDuration:"00:15:00",slotMinTime:"08:00:00",slotMaxTime:"19:00:00",themeSystem:"bootstrap",bootstrapFontAwesome:!1,buttonText:{today:"Today",month:"Month",week:"Week",day:"Day",list:"List",prev:"Prev",next:"Next"},initialView:"dayGridMonth",handleWindowResize:!0,height:s(window).height()-200,headerToolbar:{left:"prev,next today",center:"title",right:"dayGridMonth,timeGridWeek,timeGridDay,listMonth"},initialEvents:{url:t,method:"GET"},editable:!0,droppable:!0,selectable:!0,dateClick:function(e){a.onSelect(e)},eventClick:function(e){a.onEventClick(e)},eventReceive:function(e){a.onEventReceive(e)},eventDrop:function(e){a.onEventDrop(e)},eventResize:function(e){a.onEventResize(e)}}),a.$calendarObj.render(),a.$btnNewEvent.on("click",function(e){a.onSelect({date:new Date,allDay:!0})}),a.$formEvent.on("submit",function(e){e.preventDefault();var t,n=a.$formEvent[0];n.checkValidity()?a.$selectedEvent?(t={title:s("#event-title").val(),start:moment(a.$selectedEvent.start).format("YYYY-MM-DD hh:mm:ss"),allDay:a.$selectedEvent.allDay,className:s("#event-category").val(),csrfmiddlewaretoken:l},a.$selectedEvent.end&&(t.end=moment(a.$selectedEvent.end).format("YYYY-MM-DD hh:mm:ss")),s.ajax({type:"POST",url:"/apps/event/edit/"+a.$selectedEvent.extendedProps.pk,data:t,success:function(e){a.$modal.hide(),a.$selectedEvent.setProp("title",e.title),a.$selectedEvent.setProp("classNames",[e.className])},error:function(e){var t="";for(const n in e.responseJSON)t=t+n+" : "+e.responseJSON[n]+"<br />";t&&s("#msgs").html("<div class='alert alert-danger'>"+t+"</div>")}})):(t={title:s("#event-title").val(),start:a.$newEventData.date,allDay:a.$newEventData.allDay,className:s("#event-category").val()},s.ajax({type:"POST",url:o,data:{title:t.title,start:moment(t.start).format("YYYY-MM-DD hh:mm:ss"),allDay:t.allDay,className:t.className,csrfmiddlewaretoken:l},success:function(e){a.$calendarObj.addEvent(e),a.$modal.hide()},error:function(e){var t="";for(const n in e.responseJSON)t=t+n+" : "+e.responseJSON[n]+"<br />";t&&s("#msgs").html("<div class='alert alert-danger'>"+t+"</div>")}})):(e.stopPropagation(),n.classList.add("was-validated"))}),s(a.$btnDeleteEvent.on("click",function(e){var t;a.$selectedEvent&&(t=s("input[name='csrfmiddlewaretoken']").val(),s.ajax({type:"POST",url:"/apps/event/remove/"+a.$selectedEvent.extendedProps.pk,data:{csrfmiddlewaretoken:t},success:function(e){a.$selectedEvent.remove(),a.$selectedEvent=null,a.$modal.hide()},error:function(e){for(const t in e.responseJSON)console.log(t,":",e.responseJSON[t])}}))}))},s.CalendarApp=new e,s.CalendarApp.Constructor=e}(window.jQuery),function(){"use strict";window.jQuery.CalendarApp.init()}();