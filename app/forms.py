from flask_wtf import FlaskForm
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms.fields import StringField, PasswordField, BooleanField, IntegerField, SelectMultipleField
from wtforms.validators import DataRequired, Length, Email, EqualTo, NumberRange, Regexp
from app.uploadsets import *


class LoginForm(FlaskForm):
    username = StringField(
        'username',
        validators=[
            DataRequired(message=u'请输用户名!'),
            Length(4, 16, message=u'用户名必须在4-16个字符内!')
        ]
    )
    password = PasswordField(
        'password',
        validators=[
            DataRequired(message=u'请输入登录密码!'),
            Length(6, 30, message=u'登录密码长度应在6-30个字符内!')
        ]
    )
    remember_me = BooleanField('remember_me', default=False)


class SigninForm(FlaskForm):
    username = StringField(
        'username',
        validators=[
            DataRequired(message=u'请输用户名!'),
            Length(4, 16, message=u'用户名必须在4-16个字符内!')
        ]
    )
    password = PasswordField(
        'password',
        validators=[
            DataRequired(message=u'请输入登录密码!'),
            Length(6, 30, message=u'登录密码长度应在6-30个字符内!')
        ]
    )
    name = StringField(
        'name',
        validators=[
            DataRequired(message=u'请输用户名!'),
            Length(2, 16, message=u'用户名必须在2-16个字符内!')
        ]
    )
    code = StringField(
        'code',
        validators=[
            DataRequired(message=u'请输入验证码!'),
            Length(4, 4, message=u'请输入4位验证码！')
        ]
    )
    remember_me = BooleanField('remember_me', default=False)
