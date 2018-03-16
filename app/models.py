# -*- coding:utf-8 -*-
from random import Random
import hashlib, time, re
from datetime import datetime, timedelta, date
from app import db


def random_str(randomlength=8):
    '''
    获取随机盐值
    :param randomlength:盐值长度
    :return:盐
    '''
    str = ''
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    length = len(chars) - 1
    random = Random()
    for i in range(randomlength):
        str += chars[random.randint(0, length)]
    return str


def getSHA256(content):
    '''
    SHA256加密
    :param content:明文
    :return: 密文
    '''
    content = content.encode('utf8')
    SHA256 = hashlib.sha256()
    SHA256.update(content)
    return SHA256.hexdigest()


def getMD5(content):
    '''
    MD5加密(慎用)
    :param content: 明文
    :return: 密文
    '''
    MD5 = hashlib.md5()
    MD5.update(content)
    return MD5.hexdigest()


# Statics

group_type_int2str = {
    0: '其它',
    1: '课程',
    2: '活动',
}


def fun_group_type_int2str(type):
    if type in group_type_int2str:
        return group_type_int2str[type]
    else:
        return '未知'


# Models

relation_group_signers = db.Table(
    'relation_group_signers',
    db.Column('group_id', db.Integer, db.ForeignKey('Group.id')),
    db.Column('signers_id', db.Integer, db.ForeignKey('User.id'))
)


class Sign(db.Model):
    __tablename__ = 'Sign'
    id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)  # sid
    dt_sign = db.Column(db.DATETIME)
    gps_lon = db.Column(db.FLOAT)
    gps_lat = db.Column(db.FLOAT)
    bt_ssid = db.Column(db.String(32))
    pass_face = db.Column(db.Boolean)
    pass_voice = db.Column(db.Boolean)
    pass_bt = db.Column(db.Boolean)
    pass_gps = db.Column(db.Boolean)
    # ForeignKey
    event_id = db.Column(db.INTEGER, db.ForeignKey('Event.id'))
    signer_id = db.Column(db.INTEGER, db.ForeignKey('User.id'))

    def __init__(self, event, signer, opt={}):
        self.signer = signer
        self.event = event
        option = {
            'gps_lon': 0.0,
            'gps_lat': 0.0,
            'bt_ssid': ""
        }
        for key, value in opt.items():
            option[key] = value
        self.gps_lon = option['gps_lon']
        self.gps_lat = option['gps_lat']
        self.bt_ssid = option['bt_ssid']
        self.dt_sign = datetime.now()
        self.pass_face = False
        self.pass_voice = False
        self.pass_bt = False
        self.pass_gps = False
        self.update()

    def passFace(self):
        self.pass_face = True
        self.update()

    def passVoice(self):
        self.pass_voice = True
        self.update()

    def passBT(self):
        self.pass_bt = True
        self.update()

    def passGPS(self):
        self.pass_gps = True
        self.update()

    def isPassFace(self):
        if self.event.use_face and not self.pass_face:
            return False
        return True

    def isPassVoice(self):
        if self.event.use_voice and not self.pass_voice:
            return False
        return True

    def isPassGPS(self):
        if self.event.use_gps and not self.pass_gps:
            return False
        return True

    def isPassBT(self):
        if self.event.use_bt and not self.pass_bt:
            return False
        return True

    def isPass(self):
        return self.isPassFace() and self.isPassVoice() and self.isPassGPS() and self.isPassBT()

    def update(self):
        db.session.add(self)
        db.session.commit()


class Event(db.Model):
    __tablename__ = 'Event'
    id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)  # eid
    name = db.Column(db.String(32))
    dt_start = db.Column(db.DATETIME)
    dt_end = db.Column(db.DATETIME)
    use_face = db.Column(db.BOOLEAN)
    use_voice = db.Column(db.BOOLEAN)
    use_gps = db.Column(db.BOOLEAN)
    use_bt = db.Column(db.BOOLEAN)
    gps_lon = db.Column(db.FLOAT)
    gps_lat = db.Column(db.FLOAT)
    bt_ssid = db.Column(db.String(32))
    group_id = db.Column(db.INTEGER, db.ForeignKey('Group.id'))
    # reloationships
    signs = db.relationship('Sign', backref='event', foreign_keys=[Sign.event_id])

    def __init__(self, group, name, dt_start, dt_end, opt={}):
        self.group_id = group.id
        self.name = name
        self.dt_start = dt_start
        self.dt_end = dt_end
        option = {
            'use_face': False,
            'use_voice': False,
            'use_gps': False,
            'use_bt': False,
            'gps_lon': 0.0,
            'gps_lat': 0.0,
            'bt_ssid': ""
        }
        for key, value in opt.items():
            option[key] = value
        self.use_face = option['use_face']
        self.use_voice = option['use_voice']
        self.use_gps = option['use_gps']
        self.use_bt = option['use_bt']
        self.gps_lon = option['gps_lon']
        self.gps_lat = option['gps_lat']
        self.bt_ssid = option['bt_ssid']
        self.update()

    def update(self):
        db.session.add(self)
        db.session.commit()


class Group(db.Model):
    __tablename__ = 'Group'
    # columns
    id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)  # gid
    name = db.Column(db.String(32))
    type = db.Column(db.INTEGER)
    leader_id = db.Column(db.INTEGER, db.ForeignKey('User.id'))
    dt_setup = db.Column(db.DATETIME)
    # relationships
    events = db.relationship('Event', backref='group', foreign_keys=[Event.group_id])
    # static
    TYPE_UNKNOWN = 0
    TYPE_CLASS = 1
    TYPE_ACTIVITY = 2

    def __init__(self, leader, name, type):
        self.leader = leader
        self.name = name
        self.type = type
        self.dt_setup = datetime.now()
        self.update()

    def update(self):
        db.session.add(self)
        db.session.commit()

    def signup(self, user):
        self.signers.append(user)
        self.update()


class User(db.Model):
    __tablename__ = 'User'
    # columns
    id = db.Column(db.INTEGER, primary_key=True, autoincrement=True)  # uid
    email = db.Column(db.String(32), index=True, unique=True)
    passwordhash = db.Column(db.String(64))
    name = db.Column(db.String(32))
    salt = db.Column(db.String(8))
    registed_face = db.Column(db.Boolean)
    registed_voice_times = db.Column(db.INTEGER)
    # relationships
    groups_own = db.relationship('Group', backref='leader', foreign_keys=[Group.leader_id])
    groups_sign = db.relationship('Group', secondary=relation_group_signers,
                                  backref=db.backref('signers', lazy='dynamic'), lazy='dynamic')
    signs = db.relationship('Sign', backref='signer', foreign_keys=[Sign.signer_id])

    def __init__(self, email, password, name):
        self.email = email
        self.name = name
        self.setPassword(password, update=False)
        self.time_submit = datetime.now()
        self.registed_face = False
        self.registed_voice_times = 0
        self.update()

    def update(self):
        db.session.add(self)
        db.session.commit()

    def setPassword(self, password, update=True):
        self.salt = random_str()
        self.passwordhash = getSHA256(password + self.salt)
        self.chpassword = True
        if update:
            self.update()

    def testPassword(self, password):
        return getSHA256(password + self.salt) == self.passwordhash

    def isSigned(self, group):
        if self.groups_sign.filter(Group.id == group.id).count() > 0:
            return True
        else:
            return False

    def hasSignedEvent(self, event):
        sign = Sign.query.filter(Sign.signer_id == self.id).filter(Sign.event_id == event.id).first()
        if sign is None:
            return False
        if sign.isPass():
            return True
        return False

    def registedFace(self):
        return self.registed_face

    def registedVoice(self):
        return self.registed_voice_times >= 5

    def registFace(self):
        self.registed_face = True
        self.update()

    def registVoice(self):
        self.registed_voice_times += 1
        self.update()

    # for flask-login

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id


'''
relation_group_signers = db.Table(
    'relation_group_signers',
    db.Column('group_id', db.Integer, db.ForeignKey('Group.id')),
    db.Column('signers_id', db.Integer, db.ForeignKey('User.id'))
)
'''

'''

class Sign(db.Model):
    __tablename__ = 'Sign'
    # columbs
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # sid
    activity_id = db.Column(db.Integer, db.ForeignKey('Activity.id'))
    signer_id = db.Column(db.Integer, db.ForeignKey('Signer.id'))
    gps_lon = db.Column(db.Float)
    gps_lat = db.Column(db.Float)
    wifiap_mac = db.Column(db.String(64))
    time_sign = db.Column(db.DateTime)

    def __init__(self, activity, signer):
        self.activity = activity
        self.signer = signer
        self.time_sign = datetime.now()
        self.update()

    def setGPSInfo(self, lon, lat):
        self.gps_lon = lon
        self.gps_lat = lat
        self.update()

    def setWifiAPInfo(self, mac):
        self.wifiap_mac = mac.upper()
        self.update()

    def update(self):
        db.session.add(self)
        db.session.commit()


class Activity(db.Model):
    __tablename__ = 'Activity'
    # columns
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # aid
    name = db.Column(db.String(64))
    group_id = db.Column(db.Integer, db.ForeignKey('Group.id'))
    time_start = db.Column(db.DateTime)
    time_end = db.Column(db.DateTime)
    use_gps = db.Column(db.Boolean)
    use_face = db.Column(db.Boolean)
    use_voice = db.Column(db.Boolean)
    use_wifiap = db.Column(db.Boolean)
    gps_lon = db.Column(db.Float)
    gps_lat = db.Column(db.Float)
    wifiap_bssid = db.Column(db.String(64))
    time_submit = db.Column(db.DateTime)

    # relations
    signs = db.relationship('Sign', backref='activity', foreign_keys=[Sign.activity_id])

    def __init__(self, group, name, time_start, time_end, use_gps, use_face, use_voice, use_wifiap):
        self.group = group
        self.name = name
        self.time_start = time_start
        self.time_end = time_end
        self.use_gps = use_gps
        self.use_face = use_face
        self.use_voice = use_voice
        self.use_wifiap = use_wifiap
        self.time_submit = datetime.now()
        self.gps_lon = 0
        self.gps_lat = 0
        self.wifiap_bssid = ""
        self.update()

    def setGPSInfo(self, lon, lat):
        self.gps_lon = lon
        self.gps_lat = lat
        self.update()

    def setWifiAPInfo(self, bssid):
        self.wifiap_bssid = bssid.upper()
        self.update()

    def update(self):
        db.session.add(self)
        db.session.commit()


class Group(db.Model):
    __tablename__ = 'Group'
    # columns
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # gid
    name = db.Column(db.String(64))
    creator_id = db.Column(db.Integer, db.ForeignKey('Leader.id'))
    time_submit = db.Column(db.DateTime)
    # relations
    activities = db.relationship('Activity', backref='group', foreign_keys=[Activity.group_id])
    signers = db.relationship('Signer', backref='group_signed', )

    def __init__(self, creator, name):
        self.creator = creator
        self.name = name
        self.time_submit = datetime.now()
        self.update()

    def update(self):
        db.session.add(self)
        db.session.commit()


class Signer(db.Model):
    __tablename__ = 'Signer'
    # columns
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # uid
    id4group = db.Column(db.String(64))
    name = db.Column(db.String(64))  # 昵称
    group_signed_id = db.Column(db.Integer, db.ForeignKey('Group.id'))
    # statics
    identify = 'Signer'

    def __init__(self, group_signed, id4group, name):
        self.group_signed = group_signed
        self.id4group = id4group
        self.name = name
        self.update()

    def update(self):
        db.session.add(self)
        db.session.commit()


class Leader(db.Model):
    __tablename__ = 'Leader'
    # columns
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # uid
    username = db.Column(db.String(64), unique=True, index=True)  # 登录用户名
    salt = db.Column(db.String(8))  # 密码的盐值 防撞库
    passwordhash = db.Column(db.String(64))  # 哈希后的密码
    time_submit = db.Column(db.DateTime)
    # relations
    groups_created = db.relationship('Group', backref='creator', foreign_keys=[Group.creator_id])  # 创建的小组 一对多
    # statics
    identify = 'Leader'

    def __init__(self, username, password, name):
        self.username = username
        self.name = name
        self.setPassword(password, update=False)
        self.time_submit = datetime.now()
        self.update()

    def update(self):
        db.session.add(self)
        db.session.commit()

    def setPassword(self, password, update=True):
        self.salt = random_str()
        self.passwordhash = getSHA256(password + self.salt)
        self.chpassword = True
        if update:
            self.update()

    def testPassword(self, password):
        return getSHA256(password + self.salt) == self.passwordhash

    # for flask-login

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id
'''
