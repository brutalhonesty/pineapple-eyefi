#!/usr/bin/env python

from flask import Flask, request, redirect, url_for, abort, render_template, make_response, after_this_request
from werkzeug import secure_filename
import xml.etree.cElementTree as ET
import xml.etree.ElementTree as xml
import os
import md5
import random
import string

# Eye-Fi Port
PORT = 59278
# KEY for Eye-Fi Mobi Cards
KEY = '00000000000000000000000000000000'
# Client cnonce
SESSION = ''
FILE_ID = 1
UPLOAD_FOLDER = '/sd/uploads'

# Create application.
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Env vars.
# app.config.from_envvar('FLASKR_SETTINGS', silent=False)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/soap/eyefilm/v1', methods=['POST'])
def start_session():
    if 'soapaction' not in request.headers:
        abort(400)
    header_value = request.headers['soapaction']
    if header_value == 'urn:StartSession':
        root = ET.fromstring(request.data)
        for child in root:
            for step_child in child:
                for step_step_child in step_child:
                    if step_step_child.tag == 'macaddress':
                        macaddress = step_step_child.text
                    elif step_step_child.tag == 'cnonce':
                        cnonce = step_step_child.text
                    elif step_step_child.tag == 'transfermode':
                        transfermode = step_step_child.text
                    elif step_step_child.tag == 'transfermodetimestamp':
                        transfermode_timestamp = step_step_child.text
        new_cnonce = _get_new_cnonce()
        _set_cnonce(new_cnonce)

        credential = _get_credential(
            str(macaddress) + str(new_cnonce) + str(KEY))

        resp = make_response(render_template(
            'start_session_response.xml',
            credential=credential,
            snonce=SESSION,
            transfermode=transfermode,
            transfermode_timestamp=transfermode_timestamp))
        resp.headers['Content-Type'] = 'application/xml'
        return resp
    elif header_value == 'urn:GetPhotoStatus':
        root = ET.fromstring(request.data)
        for child in root:
            for step_child in child:
                for step_step_child in step_child:
                    if step_step_child.tag == 'credential':
                        credential = step_step_child.text
                    elif step_step_child.tag == 'macaddress':
                        macaddress = step_step_child.text
                    elif step_step_child.tag == 'filename':
                        file_name = step_step_child.text
                    elif step_step_child.tag == 'filesize':
                        file_size = step_step_child.text
                    elif step_step_child.tag == 'filesignature':
                        file_sig = step_step_child.text
                    elif step_step_child.tag == 'flags':
                        flags = step_step_child.text
        old_credential = _get_credential(
            str(macaddress) + str(SESSION) + str(KEY))
        if old_credential == credential:
            @after_this_request
            def set_file_id(resp):
                global FILE_ID
                FILE_ID += 1
                return resp
            resp = make_response(render_template(
                'get_photo_status_response.xml',
                file_id=FILE_ID,
                offset=0))
            resp.headers['Content-Type'] = 'application/xml'
            return resp
        else:
            abort(400)
    else:
        return 'Who knows!?'


@app.route('/api/soap/eyefilm/v1/upload', methods=['POST'])
def capture_upload():
    if 'soapaction' not in request.headers:
        abort(400)
    # We ignore this for now..
    integrity_digest = request.form['INTEGRITYDIGEST']
    upload_data = request.form['SOAP']
    # Image object
    image = request.files['FILENAME']
    # Get file from req
    filename = secure_filename(image.filename)
    # Save file to upload dir
    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    root = ET.fromstring(upload_data)
    for child in root:
            for step_child in child:
                for step_step_child in step_child:
                    if step_step_child.tag == 'fileid':
                        file_id = step_step_child.text
                    elif step_step_child.tag == 'macaddress':
                        macaddress = step_step_child.text
                    elif step_step_child.tag == 'filename':
                        pass
                    elif step_step_child.tag == 'filesize':
                        filesize = step_step_child.text
                    elif step_step_child.tag == 'filesignature':
                        file_sig = step_step_child.text
                    elif step_step_child.tag == 'encryption':
                        encryption = step_step_child.text
                    elif step_step_child.tag == 'flags':
                        flags = step_step_child.text
    resp = make_response(render_template('upload_photo_response.xml'))
    resp.headers['Content-Type'] = 'application/xml'
    return resp


def _get_new_cnonce():
    m = md5.new()
    random_word = '.'.join(random.choice(string.lowercase) for i in range(40))
    m.update(random_word)
    return m.hexdigest()


def _set_cnonce(cnonce):
    global SESSION
    SESSION = cnonce


def _get_credential(plaintext):
    m = md5.new()
    m.update(plaintext)
    return m.hexdigest()

if __name__ == '__main__':
    app.debug = True
    app.run(port=PORT)
