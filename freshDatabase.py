#!/usr/bin/python3
from app import db
import os


def createUserSpace(user):
    # 创建用户空间
    basepath = os.path.join(os.getcwd(), "app/res")
    userspacepath = os.path.join(basepath, str(user.id))
    wavpath = os.path.join(userspacepath, 'wav')
    os.makedirs(userspacepath)
    os.makedirs(wavpath)


db.create_all()
'''
from app.models import *

u = User('617154443@qq.com', '123456', '孟爻')
createUserSpace(u)

g = Group(u, '课程1', Group.TYPE_CLASS)

for i, username in zip(range(5), ['111111', '222222', '333333', '444444', '555555']):
    name = username + '@123.com'
    uu = User(name, '123456', name)
    createUserSpace(uu)
    g.signup(uu)

# for j in range(5):
name = 'event-' + str(1)
opts = {
    'use_face': True,
    'use_voice': True,
    'use_bt': True,
    'bt_ssid': "F8:A4:5F:03:5E:3B",
}
e = Event(g, name, datetime.now(), datetime.now() + timedelta(days=1), opt=opts)
'''