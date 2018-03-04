from flask import current_app
import os
import subprocess

def verifyFace(samplePath,dataPath):
    path = current_app.config['FACEVERIFY_PATH']
    bin = './fr'
    cmd = '%s %s %s' %(bin,samplePath,dataPath)
    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,cwd=path)
    confidence = pipe.stdout.read()
    try:
        confidence = float(confidence)
    except:
        confidence = -1
    return confidence

def trainVoiceModel(sampleDirPath,modelPath):
    path = current_app.config['VOICEVERIFY_PATH']
    bin = './vpr train'
    cmd = '%s %s %s' % (bin, sampleDirPath, modelPath)
    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, cwd=path)
    out = pipe.stdout.read()

def verifyVoice(modelPath,samplePath):
    path = current_app.config['VOICEVERIFY_PATH']
    bin = './vpr validate'
    cmd = '%s %s %s' %(bin,modelPath,samplePath)
    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,cwd=path)
    confidence = pipe.stdout.read()
    try:
        confidence = float(confidence)
    except:
        confidence = -1
    return confidence

def verifyGPS():
    pass

def verifySSID():
    pass