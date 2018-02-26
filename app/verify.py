from flask import current_app
import os
import subprocess

def verifyFace(samplePath,dataPath):
    path = current_app.config['FACEVERIFY_PATH']
    bin = './fr'
    cmd = '%s %s %s' %(bin,samplePath,dataPath)
    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,cwd=path)
    confidence = pipe.stdout.read()
    return confidence

def verifyVoice(samplePath,dataPath):
    path = current_app.config['VOICEVERIFY_PATH']
    bin = './vpr'
    cmd = '%s %s %s' %(bin,samplePath,dataPath)
    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,cwd=path)
    confidence = pipe.stdout.read()
    return confidence

def verifyGPS():
    pass

def verifySSID():
    pass