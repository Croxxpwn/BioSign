from app import app, lm, csrf
from flask import render_template, redirect, url_for, jsonify, flash, session, g, abort, request
from flask_login import login_required, login_user, logout_user, current_user
from flask_jwt import jwt_required, current_identity
from app.identifyingcode import drawIdentifyingCode
from app.models import *
from app.forms import *
import os
from functools import wraps

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


def authenticate(email, password):
    u = User.query.filter(User.email == email).first()
    if (u is None):
        error_handler(u'找不到用户')
    else:
        if (u.testPassword(password)):
            return u
        else:
            error_handler(u'密码不正确')


def identity(payload):
    id = payload['identity']
    return User.query.filter(User.id == id).first()


# JSON models

STATUS_SUCCESS = 200
STATUS_ACCESS_DENIED = 403
STATUS_NOT_FOUND = 404


def getJsonResponse(status, content):
    data = {'status_code': status, 'content': content}
    return jsonify(data)


app.jinja_env.globals['fun_group_type_int2str'] = fun_group_type_int2str


# Test

def renderDebug(url, **kw):
    if os.path.exists('app/templates/' + url):
        return render_template(url, **kw)
    else:
        return render_template('debug.' + url, **kw)


# CSRF
def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        csrf.protect()
        return f(*args, **kwargs)

    return decorated_function


# views

@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
@csrf_required
def index():
    return renderDebug('index.html')


@app.route('/login', methods=['GET', 'POST'])
@csrf_required
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
@csrf_required
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/signup', methods=['GET', 'POST'])
@csrf_required
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
@csrf_required
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
@csrf_required
@login_required
def group(gid):
    group = Group.query.filter(Group.id == gid).first()
    if group is None:
        abort(404)
    user = User.query.filter(User.id == current_user.id).first()
    if group.leader is not user:
        abort(403)
    return renderDebug('group.html', group=group)


# Ajax
@app.route('/ajax/getIdentifyingcode', methods=['POST'])
@csrf_required
def getIdentifyingcode():
    code_img, code_text = drawIdentifyingCode()
    session['code_text'] = code_text
    code_uri = '/static/tmp/code/' + getSHA256(code_text)
    return jsonify({'code_uri': code_uri})


@app.route('/ajax/validate/email/<email>/unique', methods=['POST'])
@csrf_required
def ajax_validate_username_unique(email):
    flag = True
    if User.query.filter(User.email == email).count() > 0:
        flag = False
    res = {'result': flag}
    return getJsonResponse(STATUS_SUCCESS, res)


# Mobile

@app.route('/mobile/userinfo', methods=['POST'])
@jwt_required()
def mobile_userInfo():
    user = current_identity
    data = {
        'uid': user.id,
        'email': user.email,
        'name': user.name,
    }
    return getJsonResponse(STATUS_SUCCESS, data)


@app.route('/mobile/group/own', methods=['POST'])
@jwt_required()
def mobile_group_own():
    user = current_identity
    groups = sorted(user.groups_own, key=lambda group: group.dt_setup, reverse=True)
    data = [{
        'gid': group.id,
        'name': group.name,
        'type': group.type,
        'leader_id': group.leader_id,
        'leader_email': group.leader.email,
        'leader_name': group.leader.name,
    } for group in groups]
    return getJsonResponse(STATUS_SUCCESS, data)


@app.route('/mobile/group/sign', methods=['POST'])
@jwt_required()
def mobile_group_sign():
    user = current_identity
    groups = user.groups_sign.order_by(db.desc(Group.dt_setup)).all()
    data = [{
        'gid': group.id,
        'name': group.name,
        'type': group.type,
        'leader_id': group.leader_id,
        'leader_email': group.leader.email,
        'leader_name': group.leader.name,
    } for group in groups]
    return getJsonResponse(STATUS_SUCCESS, data)


@app.route('/mobile/group/<gid>', methods=['POST'])
@jwt_required()
def mobile_group(gid):
    pass


@app.route('/mobile/group/<gid>/event', methods=['POST'])
@jwt_required()
def mobile_group_event(gid):
    user = current_identity
    group = Group.query.filter(Group.id == gid).first()
    if group is None:
        return getJsonResponse(STATUS_NOT_FOUND, None)
    if (group.leader_id != user.id) and (not user.isSigned(group)):
        return getJsonResponse(STATUS_ACCESS_DENIED, None)
    events = group.events
    data = [{
        'eid': event.id,
        'name': event.name,
        'dt_start': event.dt_start.strftime("%Y-%m-%d %H:%M:%S"),
        'dt_end': event.dt_end.strftime("%Y-%m-%d %H:%M:%S"),
        'use_face':event.use_face,
        'use_voice':event.use_voice,
        'use_gps':event.use_gps,
        'gps_lon':event.gps_lon,
        'gps_lat':event.gps_lat,
        'use_bt':event.use_bt,
        'bt_ssid':event.bt_ssid,
    } for event in events]
    return getJsonResponse(STATUS_SUCCESS, data)


@app.route('/mobile/group/<gid>/event/<eid>/sign', methods=['POST'])
@jwt_required()
def mobile_group_event_sign(gid, eid):
    pass
