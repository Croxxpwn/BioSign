from flask_wtf import FlaskForm
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms.fields import StringField, PasswordField, BooleanField, IntegerField, SelectMultipleField, DateTimeField, \
    FloatField
from wtforms.validators import DataRequired, Length, Email, EqualTo, NumberRange, Regexp
from app.uploadsets import *


class LoginForm(FlaskForm):
    email = StringField(
        'email',
        validators=[
            DataRequired(message='请输入登录邮箱!'),
            Length(1, 32, message='登录邮箱必须在1-32个字符内!'),
            Email(message='请输入合法的邮箱帐号!')
        ]
    )
    password = PasswordField(
        'password',
        validators=[
            DataRequired(message='请输入登录密码!'),
            Length(6, 30, message='登录密码长度应在6-30个字符内!')
        ]
    )
    remember_me = BooleanField('remember_me', default=False)


class SignupForm(FlaskForm):
    email = StringField(
        'email',
        validators=[
            DataRequired(message='请输入登录邮箱!'),
            Length(1, 32, message='登录邮箱必须在1-32个字符内!'),
            Email(message='请输入合法的邮箱帐号!')
        ]
    )
    password = PasswordField(
        'password',
        validators=[
            DataRequired(message='请输入登录密码!'),
            Length(6, 30, message='登录密码长度应在6-30个字符内!')
        ]
    )
    name = StringField(
        'name',
        validators=[
            DataRequired(message='请输用户名!'),
            Length(2, 8, message='用户名必须在2-8个字符内!')
        ]
    )
    code = StringField(
        'code',
        validators=[
            DataRequired(message='请输入验证码!'),
            Length(4, 4, message='请输入4位验证码！')
        ]
    )


class GroupNewForm(FlaskForm):
    name = StringField(
        'name',
        validators=[
            DataRequired('请输入小组名!'),
            Length(1, 16, message='小组名必须在1-16个字符内!')
        ]
    )
    type = IntegerField(
        'type',
        validators=[],
        default=0
    )
    code = StringField(
        'code',
        validators=[
            DataRequired(message='请输入验证码!'),
            Length(4, 4, message='请输入4位验证码！')
        ]
    )


class EventNewForm(FlaskForm):
    name = StringField(
        'name',
        validators=[
            DataRequired('请输入活动名!'),
            Length(1, 16, message='活动名必须在1-16个字符内!')
        ]
    )
    dt_start = DateTimeField(
        'dt_start',
        format="%Y-%m-%dT%H:%M",
        validators=[
            DataRequired('请输入开始时间!'),
        ]
    )
    dt_end = DateTimeField(
        'dt_end',
        format="%Y-%m-%dT%H:%M",
        validators=[
            DataRequired('请输入开始时间!'),
        ]
    )
    use_face = BooleanField(
        'use_face',
        validators=[]
    )
    use_voice = BooleanField(
        'use_voice',
        validators=[]
    )
    use_bt = BooleanField(
        'use_bt',
        validators=[]
    )
    bt_ssid = StringField(
        'bt_ssid',
        validators=[]
    )


class AdvancedSignupForm(FlaskForm):
    email = StringField(
        'email',
        validators=[
            DataRequired(message='请输入登录邮箱!'),
            Length(1, 32, message='登录邮箱必须在1-32个字符内!'),
            Email(message='请输入合法的邮箱帐号!')
        ]
    )
    password = PasswordField(
        'password',
        validators=[
            DataRequired(message='请输入登录密码!'),
            Length(6, 30, message='登录密码长度应在6-30个字符内!')
        ]
    )
    name = StringField(
        'name',
        validators=[
            DataRequired(message='请输用户名!'),
            Length(2, 8, message='用户名必须在2-8个字符内!')
        ]
    )
    code = StringField(
        'code',
        validators=[
            DataRequired(message='请输入验证码!'),
            Length(4, 4, message='请输入4位验证码！')
        ]
    )