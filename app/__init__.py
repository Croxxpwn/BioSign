import pymysql

pymysql.install_as_MySQLdb()

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_jwt import JWT
from flask_wtf import CSRFProtect

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
lm = LoginManager(app)
CSRFProtect(app)

from app import views, models, forms
# jwt = JWT(app)
