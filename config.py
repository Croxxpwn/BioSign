# -*- coding:utf-8 -*-

import os
import datetime

# SQLALCHEMY

basedir = os.path.abspath(os.path.dirname(__file__))

BASE_DIR = basedir

SQLALCHEMY_DATABASE_URI = 'mysql+mysqldb://biosign_master:Croxx970327@localhost:3306/biosign?charset=utf8mb4'
SQLALCHEMY_TRACK_MODIFICATIONS = False

# FORM

CSRF_ENABLED = True
SECRET_KEY = "04c47cc2f0e4a472a3fff1c19cc96c4e2f2901a1396d6b7e5a993769511ca1e5"

# JWT

JWT_AUTH_URL_RULE = '/jwt/login'
JWT_EXPIRATION_DELTA = datetime.timedelta(hours=1)

# static values

SUCCESS = 20000


# uploadsets

UPLOADED_XLS_DEST = 'app/tmp'
UPLOADED_IMG_DEST = 'app/tmp'