from django import template

register = template.Library()

@register.filter(name='range')
def filter_range(start, end):
  return range(start, end)

@register.filter(name='index')
def index(indexable, i):
    return indexable[i]