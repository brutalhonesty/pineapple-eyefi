#!/usr/bin/env python

from flask import Flask, request, redirect, url_for, abort, render_template, make_response, after_this_request
import flickrapi
from werkzeug import secure_filename
import xml.etree.cElementTree as ET
import xml.etree.ElementTree as xml
import os
import md5
import tarfile
import hashlib
import binascii
import random
import string
import webbrowser

# Eye-Fi Port
PORT = 59278
# KEY for Eye-Fi Mobi Cards
KEY = u'00000000000000000000000000000000'
# Server nonce
SERVER_CRED = ''
# Client nonce
SESSION = ''
FILE_ID = 1
# UPLOAD_FOLDER = '/sd/uploads'
UPLOAD_FOLDER = '/tmp'
FLICKR_API_KEY = u'034800f3a9eb9d88d054c9d00a67d82e'
FLICKR_API_SECRET = u'fa6a19f351f9aced'

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
    if 'Soapaction' not in request.headers:
        abort(400)
    header_value = request.headers['Soapaction']
    if header_value == '"urn:StartSession"':
        app.logger.info('Running Start session..')
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
        credential = _get_credential(macaddress, cnonce, KEY)
        _set_cnonce(credential)
        new_snonce = _get_new_snonce()
        _set_snonce(new_snonce)
        resp = make_response(render_template(
            'start_session_response.xml',
            credential=credential,
            snonce=SERVER_CRED,
            transfermode=transfermode,
            transfermode_timestamp=transfermode_timestamp))
        resp.headers['Content-Type'] = 'text/xml; charset="utf-8"'
        resp.headers['Connection'] = 'keep-alive'
        return resp
    elif header_value == '"urn:GetPhotoStatus"':
        app.logger.info('Running Get Photo Status..')
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
        old_credential = _get_credential(macaddress, KEY, SERVER_CRED)
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
            resp.headers['Content-Type'] = 'text/xml; charset="utf-8"'
            resp.headers['Connection'] = 'keep-alive'
            return resp
        else:
            abort(400)
    else:
        abort(400)


@app.route('/api/soap/eyefilm/v1/upload', methods=['POST'])
def capture_upload():
    app.logger.info('Running file upload...')
    app.logger.info(request.headers)
    app.logger.info(request.form)
    app.logger.info(request.files)
    # We ignore this for now..
    integrity_digest = request.form['INTEGRITYDIGEST']
    app.logger.info('integrity_digest')
    app.logger.info(integrity_digest)
    upload_data = request.form['SOAPENVELOPE']
    app.logger.info('upload_data')
    app.logger.info(upload_data)
    # Image object
    image_tar = request.files['FILENAME']
    app.logger.info('image_tar')
    app.logger.info(image_tar)
    # Get file from req
    tar_filename = secure_filename(image_tar.filename)
    image_filename = tar_filename.rsplit('.', 1)[0]
    app.logger.info('image_filename')
    app.logger.info(image_filename)
    # Save file to upload dir
    tar_file_path = os.path.join(app.config['UPLOAD_FOLDER'], tar_filename)
    app.logger.info('tar_file_path')
    app.logger.info(tar_file_path)
    image_tar.save(tar_file_path)
    image_file_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
    app.logger.info('image_file_path')
    app.logger.info(image_file_path)
    ar = tarfile.open(tar_file_path, mode='r')
    ar.extractall(path=app.config['UPLOAD_FOLDER'])
    ar.close()

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

    @after_this_request
    def flickr(resp):
        _flickr_upload_photo(image_filename, image_file_path)
        return resp
    return render_template('upload_photo_response.xml')


def _flickr_upload_photo(file_name, file_path):
    flickr = flickrapi.FlickrAPI(FLICKR_API_KEY, FLICKR_API_SECRET)
    if not flickr.token_valid(perms=u'write'):
        # Get a request token
        flickr.get_request_token(oauth_callback='oob')
        # Open a browser at the authentication URL. Do this however
        # you want, as long as the user visits that URL.
        authorize_url = flickr.auth_url(perms=u'write')
        webbrowser.open_new_tab(authorize_url)
        # Get the verifier code from the user. Do this however you
        # want, as long as the user gives the application the code.
        verifier = unicode(raw_input('Verifier code: '))
        # Trade the request token for an access token
        flickr.get_access_token(verifier)
        return flickr.upload(
            is_public=1,
            fileobj=open(file_path, 'rb'),
            filename=file_name,
            content_type=1,
            format='rest')
    else:
        return flickr.upload(
            is_public=1,
            fileobj=open(file_path, 'rb'),
            filename=file_name,
            content_type=1,
            format='rest')


def _get_new_snonce():
    m = md5.new()
    random_word = '.'.join(random.choice(string.lowercase) for i in range(40))
    m.update(random_word)
    return m.hexdigest()


def _set_cnonce(cnonce):
    global SESSION
    SESSION = cnonce


def _set_snonce(credential):
    global SERVER_CRED
    SERVER_CRED = credential


def _get_credential(mac, cnonce, key):
    cred_str = mac + cnonce + key
    bin_cred_str = binascii.unhexlify(cred_str)
    m = hashlib.md5()
    m.update(bin_cred_str)
    return m.hexdigest()

if __name__ == '__main__':
    app.debug = True
    app.run(port=PORT, host='0.0.0.0')
