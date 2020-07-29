import hmac
import hashlib
import traceback
import itertools
import time
import os

from tqdm import tqdm
from filecrypt import key_id, token_b64encode

_retry_range = lambda retries: itertools.cycle([None]) if retries is None else range(retries)

def upload(path, file_id, size, base_url, api_key, chunk_size=int(10e6), progress=True, max_retries=None):
    import requests

    with tqdm(total=size, unit='B', unit_scale=True, disable=(not progress)) as pbar, open(path, 'rb') as f:
        pos = 0
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            hash = hashlib.sha3_256()
            hash.update(chunk)
            hash = hash.digest()

            content_range = f'bytes {pos}-{pos+len(chunk)-1}/{size}'
            pos += len(chunk)

            mac = hmac.new(api_key, digestmod='sha3_256')
            mac.update(file_id.encode())
            mac.update(hash)
            mac.update(content_range.encode())
            
            post_url = '/'.join([
                    base_url,
                    key_id(api_key),
                    file_id,
                    token_b64encode(mac.digest()),
                    token_b64encode(hash)])

            for attempt in _retry_range(max_retries):
                try:
                    res = requests.post(post_url, files={'chunk': chunk}, headers={'content-range': content_range})
                    break
                except requests.exceptions.RequestException as e:
                    print(f'Upload error: {type(e).__name__}')
                    time.sleep(1)
                    print('Retrying.')
            else:
                print(f'Repeated errors uploading. Exiting.')
                print(f'Leaving encrypted file under: {path}')
                sys.exit(1)
            pbar.update(len(chunk))

    os.remove(path)

