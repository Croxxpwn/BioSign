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
from collections import defaultdict

# Configs and View for Login

lm.login_view = 'mobile_login'
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
        if True:
        # if 'code_text' in session and code.upper() == session['code_text']:
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
        if True:
        # if 'code_text' in session and code.upper() == session['code_text']:
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
        if True:
        # if 'code_text' in session and code.upper() == session['code_text']:
            user = User.query.filter(User.email == email).first()
            if user is None:
                user = User(email, password, name)
                createUserSpace(user)
                login_user(user, True)
                return redirect(url_for('mobile_index'))
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
        if True:
        # if 'code_text' in session and code.upper() == session['code_text']:
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

    events = sorted(group.events, key=lambda event: event.dt_start)
    count_signers = group.signers.count()
    count_pass = [len(event.signs) for event in events]
    rate_sign = [x / count_signers for x in count_pass]
    rate_labels = [event.name for event in events]
    count_face = 0
    count_voice = 0
    count_bt = 0
    for event in events:
        if event.use_face:
            count_face += 1
        if event.use_voice:
            count_voice += 1
        if event.use_bt:
            count_bt += 1
    rate_face = count_face / len(events) if len(events) != 0 else 0
    rate_voice = count_voice / len(events) if len(events) != 0 else 0
    rate_bt = count_bt / len(events) if len(events) != 0 else 0
    rate_sign_ava = 0
    for rate in rate_sign:
        rate_sign_ava += rate
    rate_sign_ava = rate_sign_ava / len(events) if len(events) != 0 else 0
    jsondata = {
        'rate_sign': rate_sign,
        'rate_labels': rate_labels,
        'rate_face': rate_face,
        'rate_voice': rate_voice,
        'rate_bt': rate_bt,
        'rate_sign_ava': rate_sign_ava,
    }
    jsondata = json.dumps(jsondata)
    return render_template('mobile.group_detail.html', own=own, group=group, jsondata=jsondata)


@app.route('/mobile/group/<gid>/addsigner', methods=['GET', 'POST'])
@csrf_required
@login_required
def mobile_group_addsigner(gid):
    user = User.query.filter(User.id == current_user.id).first()
    group = Group.query.filter(Group.id == gid).first()
    if group is None:
        abort(404)
    if group.leader_id != user.id:
        abort(403)
    addsignerform = AddSignerForm()
    if addsignerform.validate_on_submit():
        email = addsignerform.email.data
        u = User.query.filter(User.email == email).first()
        if u is None:
            flash("用户不存在!")
        elif u.isSigned(group):
            flash("用户已在小组中!")
        else:
            group.signup(u)
            return redirect(url_for('mobile_group_detail', gid=gid))
    return render_template("mobile.addsigner.html", addsignerform=addsignerform)


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
        if dt_end > dt_start:
            if dt_end > datetime.now():
                event = Event(group, name, dt_start, dt_end, option)
                return redirect(url_for("mobile_group_detail", gid=gid))
            else:
                flash("截止时间需要在当前时间之后!")
        else:
            flash("截至时间需要再当前时间之前!")
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
    if datetime.now() > event.dt_end:
        return redirect(url_for("mobile_sign_after"))
    if datetime.now() < event.dt_start:
        return redirect(url_for("mobile_sign_before"))
    sign = Sign.query.filter(Sign.signer_id == user.id).filter(Sign.event_id == event.id).first()
    if sign is None:
        sign = Sign(event, user)
    if sign.isPass():
        return redirect(url_for("mobile_sign_sucess"))
    return render_template("mobile.sign.html", sign=sign)


@app.route('/mobile/sign/sucess')
@csrf_required
@login_required
def mobile_sign_sucess():
    return render_template("mobile.sign_success.html")


@app.route('/mobile/sign/after')
@csrf_required
@login_required
def mobile_sign_after():
    return render_template("mobile.sign_after.html")


@app.route('/mobile/sign/before')
@csrf_required
@login_required
def mobile_sign_before():
    return render_template("mobile.sign_before.html")


@app.route('/mobile/sign')
@csrf_required
@login_required
def mobile_sign():
    user = User.query.filter(User.id == current_user.id).first()
    groups = user.groups_sign.all()
    events = []
    for group in groups:
        for event in group.events:
            events.append(event)
    events_signing = []
    dt_now = datetime.now()
    for event in events:
        if dt_now > event.dt_start and dt_now < event.dt_end:
            events_signing.append(event)
    events_all = sorted(events, key=lambda x: x.dt_end)
    events_signing = sorted(events_signing, key=lambda x: x.dt_start)
    return render_template("mobile.signlist.html", events_all=events_all, events_signing=events_signing)


@app.route('/mobile/event/<eid>')
@csrf_required
@login_required
def mobile_event(eid):
    user = User.query.filter(User.id == current_user.id).first()
    event = Event.query.filter(Event.id == eid).first()
    if event is None:
        abort(404)
    if event.group.leader_id != user.id:
        abort(403)
    signs_all = event.signs
    signs_pass = []
    # 统计总数与通过数
    amount_signer = event.group.signers.count()
    amount_all = len(signs_all)
    amount_pass = 0
    for sign in signs_all:
        if sign.isPass():
            signs_pass.append(sign)
            amount_pass += 1
    minutes10_count = defaultdict(int)  # 每10分钟签到数
    minutes10_sum = defaultdict(int)  # 每10分钟签到累计数
    minutes10_max = 0  # 最大1分钟单位
    minutes1_count = defaultdict(int)  # 每1分钟签到数
    minutes1_sum = defaultdict(int)  # 每1分钟签到累计数
    minutes1_max = 0  # 最大1分钟单位
    for sign in signs_pass:
        delta = sign.dt_sign - event.dt_start
        seconds = delta.seconds
        minutes10 = seconds // 600
        minutes1 = seconds // 60
        if minutes10 > minutes10_max:
            minutes10_max = minutes10
        if minutes1 > minutes1_max:
            minutes1_max = minutes1
    for sign in signs_pass:
        delta = sign.dt_sign - event.dt_start
        seconds = delta.seconds
        minutes10 = seconds // 600
        minutes1 = seconds // 60
        minutes10_count[minutes10] += 1
        minutes1_count[minutes1] += 1
        for i in range(minutes10, minutes10_max + 1):
            minutes10_sum[i] += 1
        for i in range(minutes1, minutes1_max + 1):
            minutes1_sum[i] += 1
    minutes10_count_list = [minutes10_count[i] for i in range(minutes10_max + 1)]
    minutes10_sum_list = [minutes10_sum[i] for i in range(minutes10_max + 1)]
    minutes1_count_list = [minutes1_count[i] for i in range(minutes1_max + 1)]
    minutes1_sum_list = [minutes1_sum[i] for i in range(minutes1_max + 1)]
    signers = [sign.signer for sign in signs_pass]
    jsondata = {
        "amount_signer": amount_signer,
        "amount_all": amount_all,
        "amount_pass": amount_pass,
        "minutes10_count": minutes10_count_list,
        "minutes10_sum": minutes10_sum_list,
        "minutes10_max": minutes10_max,
        "minutes10_label": [i * 10 for i in range(minutes10_max + 1)],
        "minutes1_count": minutes1_count_list,
        "minutes1_sum": minutes1_sum_list,
        "minutes1_max": minutes1_max,
        "minutes1_label": [i * 1 for i in range(minutes1_max + 1)],
    }
    jsondata = json.dumps(jsondata)
    return render_template("mobile.event_detail.html", jsondata=jsondata, event=event, signers=signers)


@app.route('/mobile/user/<uid>/group/<gid>')
@csrf_required
@login_required
def mobile_user_group(uid, gid):
    user = User.query.filter(User.id == current_user.id).first()
    group = Group.query.filter(Group.id == gid).first()
    signer = User.query.filter(User.id == uid).first()
    if group is None or signer is None:
        abort(404)
    if not signer.isSigned(group) or group.leader_id != user.id:
        abort(403)
    events_sign = []
    events_unsign = []
    tdelta = timedelta(0)
    times_face = 0
    times_voice = 0
    times_bt = 0
    count_face = 0
    count_voice = 0
    count_bt = 0
    events = sorted(group.events, key=lambda event: event.dt_start)
    for event in events:
        if event.use_face:
            count_face += 1
        if event.use_voice:
            count_voice += 1
        if event.use_bt:
            count_bt += 1
        sign = Sign.query.filter(Sign.signer_id == signer.id).filter(Sign.event_id == event.id).first()
        if sign is None:
            events_unsign.append(event)
        else:
            if not sign.isPass():
                events_unsign.append(event)
            else:
                tdelta += sign.dt_sign - event.dt_start
                if sign.isPassFace():
                    times_face += 1
                if sign.isPassVoice():
                    times_voice += 1
                if sign.isPassBT():
                    times_bt += 1
                events_sign.append(event)
    rate_sign = len(events_sign) / (len(events_sign) + len(events_unsign)) if (len(events_sign) + len(
        events_unsign)) != 0 else 0
    tdelta = tdelta.seconds / 60
    if tdelta > 10:
        tdelta = 0
    else:
        tdelta = 10 - tdelta
    rate_tdelta = tdelta / 10
    rate_face = times_face / count_face if count_face != 0 else 0
    rate_voice = times_voice / count_voice if count_voice != 0 else 0
    rate_bt = times_bt / count_bt if count_bt != 0 else 0
    jsondata = {
        'rate_sign': rate_sign,
        'rate_tdelta': rate_tdelta,
        'rate_face': rate_face,
        'rate_voice': rate_voice,
        'rate_bt': rate_bt,
    }
    jsondata = json.dumps(jsondata)
    return render_template("mobile.user_group.html", signer=signer, jsondata=jsondata,
                           events_sign=events_sign, events_unsign=events_unsign)
