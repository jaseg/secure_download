#!/usr/bin/env python3

import re
import os

from flask import Flask, abort, request, Response

import filecrypt

app = Flask(__name__)
app.config.from_envvar('SECURE_DOWNLOAD_SETTINGS')
BASE64_RE = re.compile('^[A-Za-z0-9+-_]+=*$')

@app.route('/<file_id>/<token>/<filename>')
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

