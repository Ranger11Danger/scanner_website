from django import template

register = template.Library()

@register.filter
def to_scan_address_format(value):
    ips = value[1:-1].replace("'", ' ').split()
    if len(ips) > 2:
        return f"{ips[0]}, {ips[1]}, ..."
    elif len(ips) == 2:
         return f"{ips[0]}, {ips[1]}"
    elif len(ips) == 1:
        return f'{ips[0]}'
    else:
        return 'None'