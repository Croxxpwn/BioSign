#!/usr/bin/python3
from app import db

db.create_all()

from app.models import *

u = User('617154443@qq.com','123456','孟爻')
