#!/usr/bin/env python3

if __name__ != '__main__':
    raise ImportError('Command-line script cannot be imported as module')

import os
import configparser
import argparse
import sys

from tqdm import tqdm

from filecrypt import generate_keys, output_size
from api import upload

parser = argparse.ArgumentParser(description='Filecrypt secure file download encryption tool.'
        'Encrypts a file for use with the filecrypt server, and output the generated download link.')
parser.add_argument('infile')
parser.add_argument('-c', '--config', default=None, help='Config file location (default; $XDG_CONFIG_HOME/filecrypt.conf)')
parser.add_argument('-b', '--base-url', default=None, help='Base URL for link (also as config option)')
parser.add_argument('-f', '--filename', default=None, help='Download filename (default: Same as input filename)')
parser.add_argument('-n', '--no-progress', action='store_true', help='Hide progress bar')
parser.add_argument('-p', '--progress', action='store_true', help='Show progress bar (default, also as config option)')
parser.add_argument('-u', '--upload', action='store_true', help='Upload via HTTP API')
parser.add_argument('-a', '--api-key', default=None, help='HTTP upload API key')
parser.add_argument('-q', '--qrcode', action='store_true', help='Show download URL as QR Code')
parser.add_argument('--upload-chunk-size', type=int, default=None, help='HTTP upload API transfer chunk size')
parser.add_argument('--max-retries', type=int, default=None, help='HTTP upload request max retries')
args = parser.parse_args()

progress = (not args.no_progress) or args.progress
config_path = args.config or os.environ.get('XDG_CONFIG_HOME', os.environ.get('HOME') + '/.config') + '/filecrypt.conf'
base_url = args.base_url
api_key = args.api_key
out_file_size = output_size(args.infile)
upload_chunk_size = args.upload_chunk_size
max_retries = args.max_retries
if os.path.isfile(config_path):
    with open(config_path) as f:
        config = configparser.ConfigParser(defaults={'url_base': ''})
        config.read_string('[DEFAULT]\n'+f.read()) # doesn't parse simple key=value file by default m(

        if base_url is None:
            base_url = config.get('DEFAULT', 'base_url', fallback='').rstrip('/')
        if api_key is None:
            api_key = config.get('DEFAULT', 'api_key', fallback=None)
        if upload_chunk_size is None:
            upload_chunk_size = config.get('DEFAULT', 'upload_chunk_size', fallback=None)
        if max_retries is None:
           max_retries = config.get('DEFAULT', 'max_retries', fallback=None)
        if not (args.no_progress or args.progress):
            progress = config.getboolean('DEFAULT', 'progress', fallback=True)

if not os.path.isfile(args.infile):
    print(f'{infile} is not a file or directory, exiting.')
    os.exit(2)

if args.upload:
    if api_key is None:
        print(f'HTTP upload API key is required for --upload')
        ox.exit(2)
    api_key = api_key.encode()

if upload_chunk_size is None:
    upload_chunk_size = int(10e6)

download_filename = args.filename or os.path.basename(args.infile)

file_id, token, encrypt = generate_keys(download_filename)
url = f'{base_url}/{file_id}/{token}/{download_filename}'
print(url)

if args.qrcode:
    import qrcode
    qr = qrcode.QRCode()
    qr.add_data(url)
    qr.print_ascii(tty=True)

print('Encrypting...')
with tqdm(total=out_file_size, unit='B', unit_scale=True, disable=(not progress)) as pbar:
    for chunk in encrypt(args.infile):
        pbar.update(len(chunk))

print('Uploading...')
if args.upload:
    upload(path = f'{file_id}.enc',
            file_id=file_id,
            size=out_file_size,
            base_url=base_url,
            chunk_size=upload_chunk_size,
            progress=progress,
            api_key=api_key,
            max_retries=max_retries)

