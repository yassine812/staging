import datetime
import os, django
import sys
sys.path.insert(0, r"c:\Users\Yassine\audit2-main")
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
django.setup()
from django.template import Template, Context

t = Template('result: [{{ d|date:"d/m/Y"|default:other|date:"d/m/Y" }}]')
print('When d is date:', t.render(Context({'d': datetime.date(2026, 9, 18), 'other': datetime.date(2026, 9, 19)})))
print('When d is None:', t.render(Context({'d': None, 'other': datetime.date(2026, 9, 19)})))

t2 = Template('{{ quand|default:other_date|date:"d/m/Y"|linebreaksbr }}')
print('When quand is string:', repr(t2.render(Context({'quand': "Détection lors du contrôle", 'other_date': datetime.date(2026, 9, 18)}))))
