from app import app, lm
from flask import render_template, redirect, url_for, jsonify, flash, session, g, abort
from flask_login import login_required, login_user, logout_user, current_user
from app.identifyingcode import drawIdentifyingCode
from app.models import *
from app.forms import *
import os

# Configs and View for Login

lm.login_view = 'login'
lm.login_message = u'W请先登录!'


@lm.user_loader
def load_user(user_id):
    return User.query.filter(User.id == user_id).first()


@app.before_request
def before_request():
    g.user = current_user

# JWT views

def error_handler(e):
    print(e)
    return "Something bad happened", 400


def authenticate(id, password):
    u = User.query.filter(User.id==id).first()
    if (u is None):
        error_handler(u'找不到用户')
    else:
        if (u.testPassword(password)):
            return u
        else:
            error_handler(u'密码不正确')


def identity(payload):
    id = payload['identity']
    return User.query.filter(User.id==id).first()

# ajax models

STATUS_SUCCESS = 200
STATUS_ACCESS_DENY = 403
STATUS_NOT_FOUND = 404


def getJsonResponse(status, content):
    data = {'status': status, 'content': content}
    return jsonify(data)


app.jinja_env.globals['fun_group_type_int2str'] = fun_group_type_int2str

# Test

def renderDebug(url, **kw):
    if os.path.exists('app/templates/' + url):
        return render_template(url, **kw)
    else:
        return render_template('debug.' + url, **kw)


# views

@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
def index():
    return renderDebug('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    loginform = LoginForm()
    if loginform.validate_on_submit():
        email = loginform.email.data
        password = loginform.password.data
        remember_me = loginform.remember_me.data
        user = User.query.filter(User.email == email).first()
        if user is None:
            flash(u'W用户名不存在!请先注册!')
        else:
            if not user.testPassword(password):
                flash(u'D密码错误!')
            else:
                login_user(user, remember_me)
                flash(u'S登录成功!')
                return redirect(url_for('index'))
    return renderDebug('login.html', loginform=loginform)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    signupform = SignupForm()
    if signupform.validate_on_submit():
        email = signupform.email.data
        password = signupform.password.data
        name = signupform.name.data
        code = signupform.code.data
        if 'code_text' in session and code.upper() == session['code_text']:
            user = User.query.filter(User.email == email).first()
            if user is None:
                user = User(email, password, name)
                flash(u'S注册成功!请登录!')
                return redirect(url_for('login'))
            else:
                flash(u'D该用户名已被注册!')
        else:
            flash(u'D验证码不正确!')
    return renderDebug('signup.html', signupform=signupform)


@app.route('/group/new', methods=['GET', 'POST'])
@login_required
def group_new():
    groupnewform = GroupNewForm()
    if groupnewform.validate_on_submit():
        code = groupnewform.code.data
        if 'code_text' in session and code.upper() == session['code_text']:
            user = User.query.filter(User.id == current_user.id).first()
            name = groupnewform.name.data
            type = groupnewform.type.data
            group = Group(user, name, type)
            redirect(url_for('group', gid=group.id))
        else:
            flash(u'D验证码不正确!')
    return renderDebug('newgroup.html', groupnewform=groupnewform)


@app.route('/group/<gid>')
@login_required
def group(gid):
    group = Group.query.filter(Group.id == gid).first()
    if group is None:
        abort(404)
    user = User.query.filter(User.id==current_user.id).first()
    if group.leader is not user:
        abort(403)
    return renderDebug('group.html',group=group)

# ajax
@app.route('/ajax/getIdentifyingcode', methods=['POST'])
def getIdentifyingcode():
    code_img, code_text = drawIdentifyingCode()
    session['code_text'] = code_text
    code_uri = '/static/tmp/code/' + getSHA256(code_text)
    return jsonify({'code_uri': code_uri})


@app.route('/ajax/validate/email/<email>/unique', methods=['POST'])
def ajax_validate_username_unique(email):
    flag = True
    if User.query.filter(User.email == email).count() > 0:
        flag = False
    res = {'result': flag}
    return getJsonResponse(STATUS_SUCCESS, res)
