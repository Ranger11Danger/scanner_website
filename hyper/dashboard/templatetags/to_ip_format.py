from django import template

register = template.Library()

@register.filter
def to_ip_format(value):
    return value.replace('.','-')