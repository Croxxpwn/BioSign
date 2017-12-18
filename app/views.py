from app import app, lm
from flask import render_template, redirect, url_for, jsonify, flash, session
from flask_login import login_required, login_user, logout_user
from app.identifyingcode import drawIdentifyingCode
from app.models import *
from app.forms import *

# Configs and View for Login

lm.login_view = 'login'
lm.login_message = u'W请先登录!'

# ajax models

STATUS_SUCCESS = 200
STATUS_ACCESS_DENY = 403
STATUS_NOT_FOUND = 404


def getJsonResponse(status, content):
    data = {'status': status, 'content': content}
    return jsonify(data)


# app.jinja_env.globals['getOptions_tag1'] = getOptions_tag1

# views

@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    loginform = LoginForm()
    if loginform.validate_on_submit():
        username = loginform.username.data
        password = loginform.password.data
        remember_me = loginform.remember_me.data
        leader = Leader.query.filter(Leader.username == username).first()
        if leader is None:
            flash(u'W用户名不存在!请先注册!')
        else:
            if not leader.testPassword(password):
                flash(u'D密码错误!')
            else:
                login_user(leader, remember_me)
                flash(u'S登录成功!')
                return redirect(url_for('index'))
    return render_template('login.html', loginform=loginform)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    signupform = SignupForm()
    if signupform.validate_on_submit():
        username = signupform.username.data
        password = signupform.password.data
        name = signupform.name.data
        code = signupform.code.data
        if 'code_text' in session and code.upper() == session['code_text']:
            leader = Leader.query.filter(Leader.username == username).first()
            if leader is None:
                leader = Leader(username, password, name)
                flash(u'S注册成功!请登录!')
                return redirect(url_for('login'))
            else:
                flash(u'D该用户名已被注册!')
        else:
            flash(u'D验证码不正确!')
    return render_template('signup.html', signupform=signupform)


# ajax
@app.route('/ajax/getIdentifyingcode', methods=['POST'])
def getIdentifyingcode():
    code_img, code_text = drawIdentifyingCode()
    session['code_text'] = code_text
    code_uri = '/static/tmp/code/' + getSHA256(code_text)
    return jsonify({'code_uri': code_uri})


@app.route('/ajax/validate/username/<username>/unique', methods=['POST'])
def ajax_validate_username_unique(username):
    flag = True
    if Leader.query.filter(Leader.username == username).count() > 0:
        flag = False
    res = {'result': flag}
    return getJsonResponse(STATUS_SUCCESS, res)
