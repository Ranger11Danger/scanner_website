user1 = "/static/images/users/avatar-1.jpg"
user2 = "/static/images/users/avatar-2.jpg"
user3 = "/static/images/users/avatar-3.jpg"
user4 = "/static/images/users/avatar-4.jpg"
user5 = "/static/images/users/avatar-5.jpg"
user6 = "/static/images/users/avatar-6.jpg"
user7 = "/static/images/users/avatar-7.jpg"
user8 = "/static/images/users/avatar-8.jpg"
user9 = "/static/images/users/avatar-8.jpg"
user10 = "/static/images/users/avatar-10.jpg"

statisticsIndex1Dict = [
    {
        "icon": "mdi-account-multiple",
        "title": "Number of Customers",
        "name": "Customers",
        "number": "36,254",
        "text_color": "success",
        "percentage": "5.27%",
        "arrow": "mdi-arrow-up-bold",
        "unit": "Since last month",
    },
    {
        "icon": "mdi-cart-plus",
        "title": "Number of Orders",
        "name": "Orders",
        "number": "5,543",
        "text_color": "danger",
        "percentage": "1.08%",
        "arrow": "mdi-arrow-down-bold",
        "unit": "Since last month",
    },
    {
        "icon": "mdi-currency-usd",
        "title": "Average Revenue",
        "name": "Revenue",
        "number": "$6,254",
        "text_color": "danger",
        "percentage": "7.00%",
        "arrow": "mdi-arrow-down-bold",
        "unit": "Since last month",
    },
    {
        "icon": "mdi-pulse",
        "title": "Growth",
        "name": "Growth",
        "number": "+ 30.56%",
        "text_color": "success",
        "percentage": "4.87%",
        "arrow": "mdi-arrow-up-bold",
        "unit": "Since last month",
    },
]

revenueStatDist = {
    'current_week_total': "$58,254",
    'previous_week_total': "$69,524",
    'today_total': "$2,562.30",
}

revenueProgressbarDist = [
    {"place_name": "New York",  "value": "72"},
    {"place_name": "San Francisco",  "value": "39"},
    {"place_name": "Sydney",  "value": "25"},
    {"place_name": "Singapore",  "value": "61"},
]

topSellingProductsDict = [
    {
        "productName": "ASOS Ridley High Waist",
        "price": 79.49,
        "quantity": 82,
        "amount": 6518.18,
        "symbolbefore": "$",
        "date": "07 April 2018",
    },
    {
        "productName": "Marco Lightweight Shirt",
        "price": 128.5,
        "quantity": 37,
        "amount": 4754.5,
        "symbolbefore": "$",
        "date": "25 March 2018",
    },
    {
        "productName": "Half Sleeve Shirt",
        "price": 39.99,
        "quantity": 64,
        "amount": 2559.36,
        "symbolbefore": "$",
        "date": "17 March 2018",
    },
    {
        "productName": "Lightweight Jacket",
        "price": 20.0,
        "quantity": 184,
        "amount": 3680.0,
        "symbolbefore": "$",
        "date": "12 March 2018",
    },
    {
        "productName": "Marco Shoes",
        "price": 28.49,
        "quantity": 69,
        "amount": 1965.81,
        "symbolbefore": "$",
        "date": "05 March 2018",
    },

]

totalSalesDonutChartWidgetDict = [
    {"name": "Direct", "color": "primary", "amount": "$300.56"},
    {"name": "Affilliate", "color": "danger", "amount": "$135.18"},
    {"name": "Sponsored", "color": "success", "amount": "$48.96"},
    {"name": "Email", "color": "warning", "amount": "$154.02"},
]

recentActivityDict = [
    {"icon": "mdi-upload", "color": "info", "name": "You sold an item",
        "description": "Paul Burgess just purchased “Hyper - Admin Dashboard”!", "description_bold": "", "time": "5 minutes ago"},
    {"icon": "mdi-airplane", "color": "primary", "name": "Product on the Bootstrap Market",
        "description": "Dave Gamache added", "description_bold": "Admin Dashboard", "time": "30 minutes ago"},
    {"icon": "mdi-microphone", "color": "info", "name": "Robert Delaney",
        "description": "Send you message", "description_bold": '"Are you there?"', "time": "2 hours ago"},
    {"icon": "mdi-upload", "color": "primary", "name": "Audrey Tobey",
        "description": "Uploaded a photo", "description_bold": '"Error.jpg"', "time": "14 hours ago"},
    {"icon": "mdi-upload", "color": "info", "name": "You sold an item",
        "description": "Paul Burgess just purchased “Hyper - Admin Dashboard”!", "description_bold": "", "time": "16 hours ago"},
    {"icon": "mdi-airplane", "color": "primary", "name": "Product on the Bootstrap Market",
        "description": "Dave Gamache added", "description_bold": "Admin Dashboard", "time": "22 hours ago"},
    {"icon": "mdi-microphone", "color": "info", "name": "Robert Delaney",
        "description": "Send you message", "description_bold": '"Are you there?"', "time": "2 days ago"},
]


activeUsersStatDict = {"count": 121, "arrow": "up",
                       "color": "success", "per": "5.27%", "time": "Since last month"}
viewsPerMinuteStatDict = {"count": 560, "arrow": "down",
                          "color": "danger", "per": "1.08%", "time": "Since previous week"}

viewsPerMinuteDict = [
    {"page": "/hyper/dashboard-analytics", "views": "25", "bounce_rate": "87.5%"},
    {"page": "/hyper/dashboard-crm", "views": "15", "bounce_rate": "21.48%"},
    {"page": "/ubold/dashboard", "views": "10", "bounce_rate": "63.58%"},
    {"page": "/minton/home", "views": "7", "bounce_rate": "56.12%"},
]

sessionsOsStatDict = {"online_system": "6,510", "offline_system": "2,031"}


channelsDict = [
    {"channel": "Direct", "visits": "2,050", "progress": "65", "color" : "primary"},
    {"channel": "Organic Search", "visits": "1,405", "progress": "45", "color" : "info"},
    {"channel": "Refferal", "visits": "750", "progress": "30", "color" : "warning"},
    {"channel": "Social", "visits": "540", "progress": "25", "color" : "danger"},
]

socialMediaTrafficDict = [
    {"network": "Facebook", "visits": "2,250", "progress": "65"},
    {"network": "Instagram", "visits": "1,501", "progress": "45"},
    {"network": "Twitter", "visits": "750", "progress": "30"},
    {"network": "LinkedIn", "visits": "540", "progress": "25"},
]


engagementOverviewDict = [
    {"duration": "0-30", "sessions": "2,250", "views": "4,250"},
    {"duration": "31-60", "sessions": "1,501", "views": "2,050"},
    {"duration": "61-120", "sessions": "750", "views": "1,600"},
    {"duration": "121-240", "sessions": "540", "views": "1,040"},
]



statisticsCRMDict = {
    "CampaignSent" : {
        "number": "9,184",
        "per": "3.27%",
        "arrow": "up",
    },
    "NewLeads" : {
        "number": "3,254",
        "per": "5.38%",
        "arrow": "down",
    },
    "Deals" : {
        "number": "861",
        "per": "4.87%",
        "arrow": "up",
    },
    "BookedRevenue" : {
        "number": "$253k",
        "per": "11.7%",
        "arrow": "up",
    },
}

campaignsStatDict = {
    "total_sent": "6,510",
    "reached": "3,487",
    "opened": "1,568",
}

revenueStatCRMDist = {
    "current_month": "$42,025",
    "previous_month": "$74,651",
}
topPerformingDict = [
    {"user": "Jeremy Young", "role": "Senior Sales Executive",
        "leads": "187", "Deals": "154", "tasks": "49"},
    {"user": "Thomas Krueger", "role": "Senior Sales Executive",
        "leads": "235", "Deals": "127", "tasks": "83"},
    {"user": "Pete Burdine", "role": "Senior Sales Executive",
        "leads": "365", "Deals": "148", "tasks": "62"},
    {"user": "Mary Nelson", "role": "Senior Sales Executive",
        "leads": "753", "Deals": "159", "tasks": "258"},
    {"user": "Kevin Grove", "role": "Senior Sales Executive",
        "leads": "458", "Deals": "126", "tasks": "73"},
]

recentLeadsStatusDict = {
    "cold_lead": {"name": "Cold Lead", "color": "warning"},
    "lost_lead": {"name": "Lost Lead", "color": "danger"},
    "won_lead": {"name": "Won Lead", "color": "success"}
}

recentLeadsDict = [
    {"avatar": user2, "name": "Risa Pearson", "email": "richard.john@mail.com",
        "status": recentLeadsStatusDict["cold_lead"]},
    {"avatar": user3, "name": "Margaret D. Evans", "email": "margaret.evans@rhyta.com",
        "status": recentLeadsStatusDict["lost_lead"]},
    {"avatar": user4, "name": "Bryan J. Luellen", "email": "bryuellen@dayrep.com",
        "status": recentLeadsStatusDict["won_lead"]},
    {"avatar": user5, "name": "Kathryn S. Collier", "email": "collier@jourrapide.com",
        "status": recentLeadsStatusDict["cold_lead"]},
    {"avatar": user1, "name": "Timothy Kauper", "email": "thykauper@rhyta.com",
        "status": recentLeadsStatusDict["cold_lead"]},
    {"avatar": user6, "name": "Zara Raws", "email": "austin@dayrep.com",
        "status": recentLeadsStatusDict["won_lead"]},
]


statisticsProjectsDict = {
    "total_projects" : 29,
    "total_tasks" : 715,
    "members" : 31,
    "productivity" : {"data" : "93%" , "progress" : "up"}
}

projectStatusStatDict = {
    "completed" : {"data" : "64%", "type" : "up", "color" : "success"},
    "in_progress" : {"data" : "26%", "type" : "down", "color" : "primary"},
    "behind" : {"data" : "10%", "type" : "down", "color" : "danger"},
}

totalTasks = 195
completedTasks = 107

tasksStatus = {
    "completed" : {"name" : "Completed", "color" : "warning"},
    "in_progress" : {"name" : "In-progress", "color" : "danger"},
    "outdated" : {"name" : "Outdated", "color" : "success"},
}

tasksListDict = [
    {"name" : "Coffee detail page - Main Page", "due_date" : "Due in 3 days", "status" : tasksStatus["in_progress"], "assigned_to" : "Logan R. Cohn", "time_spend" : "3h 20min" },
    {"name" : "Drinking bottle graphics", "due_date" : "Due in 27 days", "status" : tasksStatus["outdated"], "assigned_to" : "Jerry F. Powell", "time_spend" : "12h 21min" },
    {"name" : "App design and development", "due_date" : "Due in 7 days", "status" : tasksStatus["completed"], "assigned_to" : "Scot M. Smith", "time_spend" : "78h 05min" },
    {"name" : "Poster illustation design", "due_date" : "Due in 5 days", "status" : tasksStatus["in_progress"], "assigned_to" : "John P. Ritter", "time_spend" : "26h 58min" },
]


recentActivitiesDict = [
    {"name" : "Soren Drouin", "avatar" : user2, "description" : 'Completed "Design new idea"...', "time" : "18 Jan 2019 11:28 pm", "project" : "Hyper Mockup"},
    {"name" : "Anne Simard", "avatar" : user6, "description" : 'Assigned task "Poster illustation design"...', "time" : "18 Jan 2019 11:09 pm", "project" : "Hyper Mockup"},
    {"name" : "Nicolas Chartier", "avatar" : user3, "description" : 'Completed "Drinking bottle graphics"...', "time" : "15 Jan 2019 09:29 pm", "project" : "Web UI Design"},
    {"name" : "Gano Cloutier", "avatar" : user4, "description" : 'Completed "Design new idea"...', "time" : "10 Jan 2019 08:36 pm", "project" : "UBold Admin"},
    {"name" : "Francis Achin", "avatar" : user5, "description" : 'Assigned task "Hyper app design"...', "time" : "08 Jan 2019 12:28 pm", "project" : "Website Mockup"},
]

yourCalendarTasksDict = [
    {"time" : "7:30 AM - 10:00 AM", "name" : "Meeting with BD Team"},
    {"time" : "10:30 AM - 11:45 AM", "name" : "Design Review - Hyper Admin"},
    {"time" : "12:15 PM - 02:00 PM", "name" : "Setup Github Repository"},
    {"time" : "5:30 PM - 07:00 PM", "name" : "Meeting with Design Studio"},
]