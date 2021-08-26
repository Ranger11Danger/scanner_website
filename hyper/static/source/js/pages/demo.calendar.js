/**
* Theme: Hyper - Responsive Bootstrap 5 Admin Dashboard
* Author: Coderthemes
* Component: Full-Calendar
*/


!function($) {
    "use strict";

    var listUrl = $("#eventurls").data("list");
    var addUrl = $("#eventurls").data("add");
    var csrfToken = $("input[name='csrfmiddlewaretoken']").val();

    var CalendarApp = function() {
        this.$body = $("body")
        this.$modal = $('#event-modal'),
        this.$calendar = $('#calendar'),
        this.$formEvent = $("#form-event"),
        this.$btnNewEvent = $("#btn-new-event"),
        this.$btnDeleteEvent = $("#btn-delete-event"),
        this.$btnSaveEvent = $("#btn-save-event"),
        this.$modalTitle = $("#modal-title"),
        this.$calendarObj = null,
        this.$selectedEvent = null,
        this.$newEventData = null
    };


    /* on resize event */
    (CalendarApp.prototype.onEventResize = function (info) {
        var event = info.event;
        var data = {
            title: event.title,
            start: moment(event.start).format("YYYY-MM-DD hh:mm:ss"),
            allDay: event.allDay,
            className: event.classNames[0],
            csrfmiddlewaretoken: csrfToken,
        }
        if (event.end) {
            data.end = moment(event.end).format(
                "YYYY-MM-DD hh:mm:ss"
            );
        }
        $.ajax({
            type: "POST",
            url: "/apps/event/edit/" + event.extendedProps.pk,
            data: data,
            success: function (res) {
            },
            error: function (error) {
                for (const field in error.responseJSON) {
                console.log(field, ":", error.responseJSON[field]);
                }
            },
        });
    }),
    /* on drop event */
    (CalendarApp.prototype.onEventDrop = function (info) {
        var event = info.event;
        var data = {
            title: event.title,
            start: moment(event.start).format("YYYY-MM-DD hh:mm:ss"),
            allDay: event.allDay,
            className: event.classNames[0],
            csrfmiddlewaretoken: csrfToken,
        }
        if (event.end) {
            data.end = moment(event.end).format(
                "YYYY-MM-DD hh:mm:ss"
            );
        }
        $.ajax({
            type: "POST",
            url: "/apps/event/edit/" + event.extendedProps.pk,
            data: data,
            success: function (res) {
            },
            error: function (error) {
                for (const field in error.responseJSON) {
                console.log(field, ":", error.responseJSON[field]);
                }
            },
        });
    }),
    /* on receive event */
    (CalendarApp.prototype.onEventReceive = function (info) {
        var event = info.event;
        $.ajax({
                type: "POST",
                url: addUrl,
                data: {
                title: event.title,
                start: moment(event.start).format("YYYY-MM-DD hh:mm:ss"),
                allDay: event.allDay,
                className: event.classNames[0],
                csrfmiddlewaretoken: csrfToken,
            },
            success: function (res) {
                event.setExtendedProp("pk", res["pk"]);
            },
            error: function (error) {
                for (const field in error.responseJSON) {
                    console.log(field, ":", error.responseJSON[field]);
                }
            },
        });
    }),


    /* on click on event */
    CalendarApp.prototype.onEventClick =  function (info) {
        this.$formEvent[0].reset();
        this.$formEvent.removeClass("was-validated");
        
        this.$newEventData = null;
        this.$btnDeleteEvent.show();
        this.$modalTitle.text('Edit Event');
        this.$modal.show();
        this.$selectedEvent = info.event;
        $("#event-title").val(this.$selectedEvent.title);
        $("#event-category").val(this.$selectedEvent.classNames[0]);
    },

    /* on select */
    CalendarApp.prototype.onSelect = function (info) {
        this.$formEvent[0].reset();
        this.$formEvent.removeClass("was-validated");
        
        this.$selectedEvent = null;
        this.$newEventData = info;
        this.$btnDeleteEvent.hide();
        this.$modalTitle.text('Add New Event');

        this.$modal.show();
        this.$calendarObj.unselect();
    },
    
    /* Initializing */
    CalendarApp.prototype.init = function() {

        this.$modal = new bootstrap.Modal(document.getElementById('event-modal'), {
            keyboard: false
        });
        
        /*  Initialize the calendar  */
        var today = new Date($.now());

        var Draggable = FullCalendar.Draggable;
        var externalEventContainerEl = document.getElementById('external-events');

        // init dragable
        new Draggable(externalEventContainerEl, {
            itemSelector: '.external-event',
            eventData: function (eventEl) {
                return {
                    title: eventEl.innerText,
                    className: $(eventEl).data('class')
                };
            }
        });

        var defaultEvents =  [{
                title: 'Meeting with Mr. Shreyu',
                start: new Date($.now() + 158000000),
                end: new Date($.now() + 338000000),
                className: 'bg-warning'
            },
            {
                title: 'Interview - Backend Engineer',
                start: today,
                end: today,
                className: 'bg-success'
            },
            {
                title: 'Phone Screen - Frontend Engineer',
                start: new Date($.now() + 168000000),
                className: 'bg-info'
            },
            {
                title: 'Buy Design Assets',
                start: new Date($.now() + 338000000),
                end: new Date($.now() + 338000000 * 1.2),
                className: 'bg-primary',
            }];

        var $this = this;

        // cal - init
        $this.$calendarObj = new FullCalendar.Calendar($this.$calendar[0], {
            slotDuration: '00:15:00', /* If we want to split day time each 15minutes */
            slotMinTime: '08:00:00',
            slotMaxTime: '19:00:00',  
            themeSystem: 'bootstrap',
            bootstrapFontAwesome: false,
            buttonText: {
                today: 'Today',
                month: 'Month',
                week: 'Week',
                day: 'Day',
                list: 'List',
                prev: 'Prev',
                next: 'Next'
            },
            initialView: 'dayGridMonth',  
            handleWindowResize: true,   
            height: $(window).height() - 200,   
            headerToolbar: {
                left: 'prev,next today',
                center: 'title',
                right: 'dayGridMonth,timeGridWeek,timeGridDay,listMonth'
            },
            initialEvents: { url: listUrl, method: "GET" },
            editable: true,
            droppable: true, // this allows things to be dropped onto the calendar !!!
            // dayMaxEventRows: false, // allow "more" link when too many events
            selectable: true,
            dateClick: function (info) { $this.onSelect(info); },
            eventClick: function(info) { $this.onEventClick(info); },
            eventReceive: function (info) {
                $this.onEventReceive(info);
            },
            eventDrop: function (info) {
                $this.onEventDrop(info);
            },
            eventResize : function (info) {
                $this.onEventResize(info);
            }
        });

        $this.$calendarObj.render();

        // on new event button click
        $this.$btnNewEvent.on('click', function(e) {
            $this.onSelect({date: new Date(), allDay: true});
        });

        // save event
        $this.$formEvent.on('submit', function(e) {
            e.preventDefault();
            var form = $this.$formEvent[0];

            // validation
            if (form.checkValidity()) {
                // edit event
                if ($this.$selectedEvent) {
                  var data = {
                    title: $("#event-title").val(),
                    start: moment($this.$selectedEvent.start).format(
                      "YYYY-MM-DD hh:mm:ss"
                    ),
                    allDay: $this.$selectedEvent.allDay,
                    className: $("#event-category").val(),
                    csrfmiddlewaretoken: csrfToken,
                  };
                  if ($this.$selectedEvent.end) {
                    data.end = moment($this.$selectedEvent.end).format(
                      "YYYY-MM-DD hh:mm:ss"
                    );
                  }
                  $.ajax({
                    type: "POST",
                    url: "/apps/event/edit/" + $this.$selectedEvent.extendedProps.pk,
                    data: data,
                    success: function (res) {
                      $this.$modal.hide();
                      $this.$selectedEvent.setProp("title", res["title"]);
                      $this.$selectedEvent.setProp("classNames", [res["className"]]);
                    },
                    error: function (error) {
                      var msg = "";
                      for (const field in error.responseJSON) {
                        msg = msg + field+" : "+error.responseJSON[field] + "<br />"
                      }
                      if (msg) {
                        $('#msgs').html("<div class='alert alert-danger'>"+msg+"</div>");
                      }
                    },
                  });
                } else {
                  // add event
                  var eventData = {
                    title: $("#event-title").val(),
                    start: $this.$newEventData.date,
                    allDay: $this.$newEventData.allDay,
                    className: $("#event-category").val(),
                  };
                  $.ajax({
                    type: "POST",
                    url: addUrl,
                    data: {
                      title: eventData.title,
                      start: moment(eventData.start).format("YYYY-MM-DD hh:mm:ss"),
                      allDay: eventData.allDay,
                      className: eventData.className,
                      csrfmiddlewaretoken: csrfToken,
                    },
                    success: function (res) {
                      $this.$calendarObj.addEvent(res);
                      $this.$modal.hide();
                    },
                    error: function (error) {
                      var msg = "";
                      for (const field in error.responseJSON) {
                        msg = msg + field+" : "+error.responseJSON[field] + "<br />"
                      }
                      if (msg) {
                        $('#msgs').html("<div class='alert alert-danger'>"+msg+"</div>");
                      }
                    },
                  });
                }
              } else {
                e.stopPropagation();
                form.classList.add('was-validated');
            }
        });

        // delete event
        $($this.$btnDeleteEvent.on('click', function(e) {
            if ($this.$selectedEvent) {
              var csrfToken = $("input[name='csrfmiddlewaretoken']").val();
              $.ajax({
                type: "POST",
                url:
                  "/apps/event/remove/" + $this.$selectedEvent.extendedProps.pk,
                data: {
                  csrfmiddlewaretoken: csrfToken,
                },
                success: function (res) {
                  $this.$selectedEvent.remove();
                  $this.$selectedEvent = null;
                  $this.$modal.hide();
                },
                error: function (error) {
                  for (const field in error.responseJSON) {
                    console.log(field, ":", error.responseJSON[field]);
                  }
                },
              });
            }
          }));
    },

   //init CalendarApp
    $.CalendarApp = new CalendarApp, $.CalendarApp.Constructor = CalendarApp
    
}(window.jQuery),

//initializing CalendarApp
function($) {
    "use strict";
    $.CalendarApp.init()
}(window.jQuery);
