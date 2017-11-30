import pymysql

pymysql.install_as_MySQLdb()

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_jwt import JWT

app = Flask(__name__)

db_password = input('Please input Database Password!\n')

app.config.from_object('config')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqldb://biosign_master:%s@localhost:3306/biosign?charset=utf8mb4' % (db_password,)

db = SQLAlchemy(app)
lm = LoginManager(app)

# from app import views,models

# jwt = JWT(app)
