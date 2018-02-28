#!/usr/bin/python3
from app import db

db.create_all()

from app.models import *

u = User('617154443@qq.com', '123456', '孟爻')

g = Group(u, '课程1', Group.TYPE_CLASS)

for i in range(5):
    name = random_str()+'@123.com'
    uu = User(name, '123456', name)
    g.signup(uu)

for j in range(5):
    name = 'event-' + str(j)
    e = Event(g, name, datetime.now(), datetime.now() + timedelta(days=1))
