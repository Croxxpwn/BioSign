from app import app, lm, csrf
from flask import render_template, redirect, url_for, jsonify, flash, session, g, abort, request
from flask_login import login_required, login_user, logout_user, current_user
from flask_jwt import jwt_required, current_identity
from app.identifyingcode import drawIdentifyingCode
from app.models import *
from app.forms import *
from functools import wraps
from app.userutils import *
from app.verify import *
import json, base64

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
STATUS_DATA_IILEGAL = 501


def getJsonResponse(status, content):
    data = {'status_code': status, 'content': content}
    return jsonify(data)


app.jinja_env.globals['fun_group_type_int2str'] = fun_group_type_int2str


# DEBUG

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
                createUserSpace(user)
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
            return redirect(url_for('group', gid=group.id))
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


@app.route('/verify/face', methods=['GET', 'POST'])
def verify_face():
    path1 = '/home/croxx/test/face1.jpg'
    path2 = '/home/croxx/test/face2.jpg'
    return verifyFace(path1, path2)


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

@app.route('/mobile/ajax/userinfo', methods=['POST'])
@jwt_required()
def mobile_ajax_userInfo():
    user = current_identity
    data = {
        'uid': user.id,
        'email': user.email,
        'name': user.name,
    }
    return getJsonResponse(STATUS_SUCCESS, data)


@app.route('/mobile/ajax/group/own', methods=['POST'])
@jwt_required()
def mobile_ajax_group_own():
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


@app.route('/mobile/ajax/group/sign', methods=['POST'])
@jwt_required()
def mobile_ajax_group_sign():
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


@app.route('/mobile/ajax/group/<gid>', methods=['POST'])
@jwt_required()
def mobile_ajax_group(gid):
    pass


@app.route('/mobile/ajax/group/<gid>/event', methods=['POST'])
@jwt_required()
def mobile_ajax_group_event(gid):
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
        'use_face': event.use_face,
        'use_voice': event.use_voice,
        'use_gps': event.use_gps,
        'gps_lon': event.gps_lon,
        'gps_lat': event.gps_lat,
        'use_bt': event.use_bt,
        'bt_ssid': event.bt_ssid,
    } for event in events]
    return getJsonResponse(STATUS_SUCCESS, data)


@app.route('/mobile/ajax/group/<gid>/event/new', methods=['POST'])
@jwt_required()
def mobile_ajax_group_event_new(gid):
    user = current_identity
    group = Group.query.filter(Group.id == gid).first()
    if group is None:
        return getJsonResponse(STATUS_NOT_FOUND, None)
    if group.leader_id != user.id:
        return getJsonResponse(STATUS_ACCESS_DENIED, None)
    data = request.get_json()
    name = data.get('name', 'untitled')
    dt_start = datetime.strptime(data.get('dt_start', '0000-01-01 00:00:00'), "%Y-%m-%d %H:%M:%S")
    dt_end = datetime.strptime(data.get('dt_start', '0000-01-01 00:00:00'), "%Y-%m-%d %H:%M:%S")
    if dt_start > datetime.now() and dt_end > dt_start:
        return getJsonResponse(STATUS_DATA_IILEGAL, None)
    option = {
        'use_face': data.get('use_face', False),
        'use_voice': data.get('use_voice', False),
        'use_gps': data.get('use_gps', False),
        'use_bt': data.get('use_bt', False),
        'gps_lon': float(data.get('gps_lon', 0.0)),
        'gps_lat': float(data.get(' gps_lat', 0.0)),
        'bt_ssid': data.get('bt_ssid', ''),
    }
    event = Event(group, name, dt_start=dt_start, dt_end=dt_end, opt=option)
    data = {
        'eid': event.id,
        'name': event.name,
        'dt_start': event.dt_start.strftime("%Y-%m-%d %H:%M:%S"),
        'dt_end': event.dt_end.strftime("%Y-%m-%d %H:%M:%S"),
        'use_face': event.use_face,
        'use_voice': event.use_voice,
        'use_gps': event.use_gps,
        'gps_lon': event.gps_lon,
        'gps_lat': event.gps_lat,
        'use_bt': event.use_bt,
        'bt_ssid': event.bt_ssid,
    }
    return getJsonResponse(STATUS_SUCCESS, data)


@app.route('/mobile/ajax/group/<gid>/event/<eid>/sign', methods=['POST'])
@jwt_required()
def mobile_ajax_group_event_sign(gid, eid):
    pass


@app.route('/mobile/ajax/register/face', methods=['POST'])
@csrf_required
@login_required
def mobile_ajax_register_face():
    user = User.query.filter(User.id == current_user.id).first()
    face = request.form.get('face', default=None)
    if face is None:
        return getJsonResponse(STATUS_DATA_IILEGAL, None)
    strs = re.match('^data:image/(jpeg|png|gif);base64,', face)  # 正则匹配出前面的文件类型去掉
    image = face.replace(strs.group(), '')
    imgdata = base64.b64decode(image)
    tmpname = random_str(16) + datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + '.jpg'
    path = os.path.join('app/static/tmp/face', tmpname)
    file = open(path, 'wb')
    file.write(imgdata)
    file.close()
    abspath = os.path.join(os.getcwd(), path)
    confidence = verifyFace(abspath, abspath)
    if confidence > 0.9:
        newpath = os.path.join('app/res/' + str(user.id), "face.jpg")
        file = open(newpath, 'wb')
        file.write(imgdata)
        file.close()
        user.registFace()
        return getJsonResponse(STATUS_SUCCESS, None)
    else:
        return getJsonResponse(STATUS_DATA_IILEGAL, None)


@app.route('/mobile/ajax/register/voice', methods=['POST'])
@csrf_required
@login_required
def mobile_ajax_register_voice():
    user = User.query.filter(User.id == current_user.id).first()
    voice = request.form.get('voice', default=None)
    if voice is None:
        return getJsonResponse(STATUS_DATA_IILEGAL, None)
    wavdata = base64.b64decode(voice)
    tmpname = random_str(16) + datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + '.wav'
    path = os.path.join('app/res/' + str(user.id) + '/wav', tmpname)
    file = open(path, 'wb')
    file.write(wavdata)
    file.close()
    if True:
        abspath_wavdir = os.path.join(os.getcwd(), 'app/res/' + str(user.id) + '/wav')
        abspath_model = os.path.join(os.getcwd(), 'app/res/' + str(user.id) + '/voice.spk')
        trainVoiceModel(abspath_wavdir, abspath_model)
        user.registVoice()
        timesleft = 5 - user.registed_voice_times
        return getJsonResponse(STATUS_SUCCESS, {'timesleft': timesleft})
    else:
        return getJsonResponse(STATUS_DATA_IILEGAL, None)


@app.route('/mobile/ajax/auth/voice', methods=['POST'])
@csrf_required
@login_required
def mobile_ajax_auth_voice():
    user = User.query.filter(User.id == current_user.id).first()
    if not user.registedVoice():
        return getJsonResponse(STATUS_ACCESS_DENIED, None)
    sid = request.form.get('sid', default=-1)
    voice = request.form.get('voice', default=None)
    sign = Sign.query.filter(Sign.id == sid).first()
    if sign is None:
        abort(404)
    if sign.signer_id != user.id:
        abort(403)
    if voice is None:
        return getJsonResponse(STATUS_DATA_IILEGAL, None)
    wavdata = base64.b64decode(voice)
    tmpname = random_str(16) + datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + '.wav'
    path = os.path.join('app/static/tmp/voice', tmpname)
    file = open(path, 'wb')
    file.write(wavdata)
    file.close()
    abspath_model = os.path.join(os.getcwd(), 'app/res/' + str(user.id) + '/voice.spk')
    abspath_sample = os.path.join(os.getcwd(), path)
    confidence = verifyVoice(abspath_model, abspath_sample)
    print(confidence)
    if confidence > 1.5:
        sign.passVoice()
        return getJsonResponse(STATUS_SUCCESS, None)
    else:
        return getJsonResponse(STATUS_DATA_IILEGAL, None)


@app.route('/mobile/ajax/auth/face', methods=['POST'])
@csrf_required
@login_required
def mobile_ajax_auth_face():
    user = User.query.filter(User.id == current_user.id).first()
    if not user.registedFace():
        return getJsonResponse(STATUS_ACCESS_DENIED, None)
    sid = request.form.get('sid', default=-1)
    face = request.form.get('face', default=None)
    sign = Sign.query.filter(Sign.id == sid).first()
    if sign is None:
        abort(404)
    if sign.signer_id != user.id:
        abort(403)
    if face is None:
        return getJsonResponse(STATUS_DATA_IILEGAL, None)
    strs = re.match('^data:image/(jpeg|png|gif);base64,', face)  # 正则匹配出前面的文件类型去掉
    image = face.replace(strs.group(), '')
    imgdata = base64.b64decode(image)
    tmpname = random_str(16) + datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + '.jpg'
    path = os.path.join('app/static/tmp/face', tmpname)
    file = open(path, 'wb')
    file.write(imgdata)
    file.close()
    abspath = os.path.join(os.getcwd(), path)
    modelpath = os.path.join(os.getcwd(), 'app/res/' + str(user.id) + '/face.jpg')
    confidence = verifyFace(abspath, modelpath)
    if confidence > 0.9:
        sign.passFace()
        return getJsonResponse(STATUS_SUCCESS, None)
    else:
        return getJsonResponse(STATUS_DATA_IILEGAL, None)


@app.route('/mobile/ajax/auth/bt', methods=['POST'])
@csrf_required
@login_required
def mobile_ajax_auth_bt():
    user = User.query.filter(User.id == current_user.id).first()
    # print(request.form)
    sid = request.form.get('sid', default=-1)
    btdata = request.form.get('btdata', default=None)
    sign = Sign.query.filter(Sign.id == sid).first()
    if sign is None:
        abort(404)
    if sign.signer_id != user.id:
        abort(403)
    if btdata is None:
        return getJsonResponse(STATUS_DATA_IILEGAL, None)
    btjson = json.loads(btdata)
    adds = btjson['addresses']
    for add in adds:
        if add == sign.event.bt_ssid:
            sign.passBT()
            return getJsonResponse(STATUS_SUCCESS, None)
    return getJsonResponse(STATUS_DATA_IILEGAL, None)


# Mobile Views

@app.route('/mobile/index')
def mobile_index():
    return render_template('mobile.index.html')


@app.route('/mobile/signup', methods=['GET', 'POST'])
@csrf_required
def mobile_signup():
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
                createUserSpace(user)
                login_user(user, True)
                return redirect(url_for('mobile_register'))
            else:
                flash(u'D该用户名已被注册!')
        else:
            flash(u'D验证码不正确!')
    return render_template('mobile.signup.html', signupform=signupform)


@app.route('/mobile/register/face', methods=['GET'])
@csrf_required
@login_required
def mobile_register_face():
    return render_template('mobile.register_face.html')


@app.route('/mobile/register/voice', methods=['GET'])
@csrf_required
@login_required
def mobile_register_voice():
    return render_template('mobile.register_voice.html')


@app.route('/mobile/login', methods=['GET', 'POST'])
@csrf_required
def mobile_login():
    loginform = LoginForm()
    if loginform.validate_on_submit():
        email = loginform.email.data
        password = loginform.password.data
        remember_me = loginform.remember_me.data
        user = User.query.filter(User.email == email).first()
        if user is None:
            flash(u'用户不存在!')
        else:
            if not user.testPassword(password):
                flash(u'密码错误!')
            else:
                login_user(user, remember_me)
                return redirect(url_for('mobile_index'))
    return render_template('mobile.login.html', loginform=loginform)


@app.route('/mobile/logout', methods=['GET', 'POST'])
@csrf_required
@login_required
def mobile_logout():
    logout_user()
    return redirect(url_for('mobile_index'))


@app.route('/mobile/group', methods=['GET'])
@csrf_required
@login_required
def mobile_group():
    user = User.query.filter(User.id == current_user.id).first()
    groups_own = sorted(user.groups_own, key=lambda group: group.dt_setup, reverse=True)
    data_group_own = [{
        'gid': group.id,
        'name': group.name,
        'type': group.type,
        'leader_id': group.leader_id,
        'leader_email': group.leader.email,
        'leader_name': group.leader.name,
    } for group in groups_own]
    groups_sign = user.groups_sign.order_by(db.desc(Group.dt_setup)).all()
    data_group_sign = [{
        'gid': group.id,
        'name': group.name,
        'type': group.type,
        'leader_id': group.leader_id,
        'leader_email': group.leader.email,
        'leader_name': group.leader.name,
    } for group in groups_sign]
    return render_template('mobile.group.html', data_group_own=data_group_own, data_group_sign=data_group_sign)


@app.route('/mobile/group/new', methods=['GET', 'POST'])
@csrf_required
@login_required
def mobile_group_new():
    groupnewform = GroupNewForm()
    if groupnewform.validate_on_submit():
        code = groupnewform.code.data
        if 'code_text' in session and code.upper() == session['code_text']:
            user = User.query.filter(User.id == current_user.id).first()
            name = groupnewform.name.data
            type = groupnewform.type.data
            group = Group(user, name, type)
            return redirect(url_for('mobile_group'))
        else:
            flash(u'D验证码不正确!')
    return render_template('mobile.group_new.html', groupnewform=groupnewform)


@app.route('/mobile/group/<gid>')
@csrf_required
@login_required
def mobile_group_detail(gid):
    user = User.query.filter(User.id == current_user.id).first()
    group = Group.query.filter(Group.id == gid).first()
    if group is None:
        abort(404)
    own = False
    if group.leader_id == user.id:
        own = True
    elif user.isSigned(group):
        own = False
    else:
        abort(403)
    return render_template('mobile.group_detail.html', own=own, group=group)


@app.route('/mobile/group/<gid>/event/new', methods=['GET', 'POST'])
@csrf_required
@login_required
def mobile_group_event_new(gid):
    user = User.query.filter(User.id == current_user.id).first()
    group = Group.query.filter(Group.id == gid).first()
    print(request.form)
    if group is None:
        abort(404)
    if group.leader_id != user.id:
        abort(403)
    eventnewform = EventNewForm()
    if eventnewform.validate_on_submit():
        name = eventnewform.name.data
        dt_start = eventnewform.dt_start.data
        dt_end = eventnewform.dt_end.data
        use_face = eventnewform.use_face.data
        use_voice = eventnewform.use_voice.data
        use_bt = eventnewform.use_bt.data
        bt_ssid = eventnewform.bt_ssid.data
        option = {
            'use_face': use_face,
            'use_voice': use_voice,
            'use_bt': use_bt,
            'bt_ssid': bt_ssid,
        }
        if dt_end > datetime.now():
            event = Event(group, name, dt_start, dt_end, option)
            return redirect(url_for("mobile_group_detail", gid=gid))
        else:
            flash("截止时间需要在当前时间之后!")
    return render_template('mobile.event_new.html', eventnewform=eventnewform)


@app.route('/mobile/event/<eid>/sign')
@csrf_required
@login_required
def mobile_event_sign(eid):
    user = User.query.filter(User.id == current_user.id).first()
    event = Event.query.filter(Event.id == eid).first()
    if event is None:
        abort(404)
    group = event.group
    if not user.isSigned(group):
        abort(403)
    sign = Sign.query.filter(Sign.signer_id == user.id).filter(Sign.event_id == event.id).first()
    if sign is None:
        sign = Sign(event, user)
    # print(sign.isPassFace(), sign.isPassVoice(), sign.isPassBT())
    if sign.isPass():
        return redirect(url_for("mobile_sign_sucess"))
    return render_template("mobile.sign.html", sign=sign)


@app.route('/mobile/sign/sucess')
@csrf_required
@login_required
def mobile_sign_sucess():
    return render_template("mobile.sign_success.html")


@app.route('/mobile/sign')
@csrf_required
@login_required
def mobile_sign():
    return redirect(url_for("mobile_index"))
