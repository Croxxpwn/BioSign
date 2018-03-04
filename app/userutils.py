from flask import current_app
import os


def createUserSpace(user):
    # 创建用户空间
    basepath = current_app.config['USER_SPACE_PATH']
    userspacepath = os.path.join(basepath, str(user.id))
    wavpath = os.path.join(userspacepath, 'wav')
    os.makedirs(userspacepath)
    os.makedirs(wavpath)
