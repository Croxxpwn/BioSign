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


'''
relation_group_signers = db.Table(
    'relation_group_signers',
    db.Column('group_id', db.Integer, db.ForeignKey('Group.id')),
    db.Column('signers_id', db.Integer, db.ForeignKey('User.id'))
)
'''


class Sign(db.Model):
    __tablename__ = 'Sign'
    # columbs
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # sid
    activity_id = db.Column(db.Integer, db.ForeignKey('Activity.id'))
    signer_id = db.Column(db.Integer, db.ForeignKey('Signer.id'))
    time_sign = db.Column(db.DateTime)

    def __init__(self, activity, signer):
        self.activity = activity
        self.signer = signer
        self.time_sign = datetime.now()
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
    time_submit = db.Column(db.DateTime)
    # relations
    signs = db.relationship('Sign', backref='activity', foreign_keys=[Sign.activity_id])

    def __init__(self, group, name, time_start, time_end, use_gps, use_face, use_voice):
        self.group = group
        self.name = name
        self.time_start = time_start
        self.time_end = time_end
        self.use_gps = use_gps
        self.use_face = use_face
        self.use_voice = use_voice
        self.time_submit = datetime.now()
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
    signers = db.relationship('Signer', backref='group_signed',)

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
    group_signed_id = db.Column(db.Integer,db.ForeignKey('Group.id'))
    # statics
    identify = 'Signer'

    def __init__(self,group_signed,id4group,name):
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
