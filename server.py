#!/usr/bin/env python3

import re
import os

import hashlib
import hmac

from flask import Flask, abort, request, Response

import filecrypt

app = Flask(__name__)

# default values
app.config['MAX_UPLOAD_SIZE'] = int(100e6)
app.config['MAX_UPLOAD_CHUNK_SIZE'] = int(100e6)

app.config.from_envvar('SECURE_DOWNLOAD_SETTINGS')

upload_keys = {}
for v in app.config.get('UPLOAD_KEYS', []):
    upload_keys[filecrypt.key_id(v)] = v

BASE64_RE = re.compile('^[A-Za-z0-9+-_]+=*$')

@app.route('/<file_id>/<token>/<filename>', methods=['GET'])
def download(file_id, token, filename):
    if not BASE64_RE.match(file_id) or len(file_id) != filecrypt.FILE_ID_LENGTH:
        abort(400, 'Invalid file ID format')
    if not BASE64_RE.match(token) or len(token) != filecrypt.TOKEN_LENGTH:
        abort(400, 'Invalid token format')

    path = f'{app.config["SERVE_PATH"]}/{file_id}.enc'
    if not os.path.isfile(path):
        abort(403) # forbidden

    size = filecrypt.payload_size(path)

    range_header = re.match('^bytes=([0-9]+)-([0-9]*)$', request.headers.get('Range', ''))
    if not range_header:
        try:
            generator = filecrypt.decrypt_generator(path, filename, token)
        except ValueError: # MAC check failed
            abort(403) # forbidden

        response = Response(generator, mimetype='application/octet-stream')
        response.headers['Content-Length'] = size
    else:
        range_start, range_end = range_header.groups()
        range_start = int(range_start)
        range_end = int(range_end) if range_end else size-1
        if range_start < 0 or range_end >= size or range_start >= range_end:
            abort(416) # range not satisfiable

        try:
            generator = filecrypt.decrypt_generator(path, filename, token, seek=range_start, end=range_end)
        except ValueError: # MAC check failed
            abort(403) # forbidden
        response = Response(generator, status=206, mimetype='application/octet-stream')
        response.headers['Content-Range'] = f'bytes {range_start}-{range_end}/{size}'
        response.headers['Content-Length'] = range_end - range_start + 1

    print(f'{request.remote_addr}: {file_id} OK')
    response.headers['Accept-Ranges'] = 'bytes'
    response.headers['Content-Disposition'] = f'attachment {filename}'
    return response

@app.route('/<key_id>/<file_id>/<token>/<filehash>', methods=['POST'])
def upload(key_id, file_id, token, filehash):
    if not BASE64_RE.match(file_id) or len(file_id) != filecrypt.FILE_ID_LENGTH:
        abort(400, 'Invalid file ID format')
    if not BASE64_RE.match(token) or len(token) != filecrypt.token_b64len(32):
        abort(400, 'Invalid token format')
    if not BASE64_RE.match(filehash) or len(filehash) != filecrypt.token_b64len(32):
        abort(400, 'Invalid hash format')
    if not BASE64_RE.match(key_id) or len(key_id) != filecrypt.token_b64len(32):
        abort(400, 'Invalid key id format')

    if request.content_length is None:
        abort(411)

    if request.content_length > app.config['MAX_UPLOAD_CHUNK_SIZE']:
        abort(413)

    if not key_id in upload_keys:
        abort(403)

    filehash = filecrypt.token_b64decode(filehash)
    token = filecrypt.token_b64decode(token)
    content_range = request.headers.get('Content-Range', 'NO CONTENT RANGE')

    mac = hmac.new(upload_keys[key_id], digestmod='sha3_256')
    mac.update(file_id.encode())
    mac.update(filehash)
    mac.update(content_range.encode())
    if not hmac.compare_digest(mac.digest(), token):
        abort(403)

    path = f'{app.config["SERVE_PATH"]}/{file_id}.enc'
    if os.path.isfile(path):
        abort(409)

    if 'chunk' not in request.files:
        abort(400, 'Invalid file payload')
    data = request.files['chunk'].read()

    hash = hashlib.sha3_256()
    hash.update(data)
    if not hmac.compare_digest(hash.digest(), filehash):
        abort(400)

    tmp_path = f'{path}.uploading'
    range_header = re.match('^bytes ([0-9]+)-([0-9]+)/([0-9]+|\*)$', content_range)
    if not range_header:
        if os.path.isfile(tmp_path):
            os.remove(tmp_path)

        with open(path, 'wb') as f:
            f.write(data)
        print(f'{request.remote_addr}: {file_id} UPLOAD')
        return 'success', 200

    else:
        range_start, range_end, size = range_header.groups()
        if size == '*':
            abort(400, 'Content-range header if used must include total size')
        try:
            range_start, range_end, size = int(range_start), int(range_end), int(size)
        except ValueError:
            abort(400)

        with open(tmp_path, 'ab') as f:
            if range_start > f.tell():
                abort(416)

            f.truncate(range_start)
            f.write(data)

        if range_end+1 == size:
            os.rename(tmp_path, path)
            print(f'{request.remote_addr}: {file_id} UPLOAD')
            return 'success', 200
        
        return 'partial', 206

