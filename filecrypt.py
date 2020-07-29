import secrets
from Cryptodome.Cipher import AES
import base64
import struct
import subprocess
import binascii
import hashlib
import os
from contextlib import contextmanager

token_b64decode = lambda token: base64.b64decode(token + '='*((3-len(token)%3)%3), b'+-')
token_b64encode = lambda token: base64.b64encode(token, b'+-').rstrip(b'=').decode()
token_b64len    = lambda nbytes: len(token_b64encode(b'0' * nbytes))

key_id = lambda key: token_b64encode(hashlib.sha3_256(b'FILECRYPT_KEY_ID'+key).digest())

FILE_ID_LENGTH = token_b64len(16)
TOKEN_LENGTH = token_b64len(16)
HEADER_LENGTH = 56

def generate_keys(download_filename, chunk_size=1000000//16):
    file_id = secrets.token_urlsafe(16)
    auth_secret = secrets.token_bytes(16)
    key = secrets.token_bytes(16)
    data_nonce = secrets.token_bytes(8)

    token_cipher = AES.new(auth_secret, AES.MODE_GCM)
    token_cipher.update(download_filename.encode())
    ciphertext, token_tag = token_cipher.encrypt_and_digest(key)
    token = token_b64encode(ciphertext)

    def encrypt(filename_in):
        with open(f'{file_id}.enc', 'wb') as fout, open(filename_in, 'rb') as fin:
            fout.write(token_cipher.nonce) # 16 bytes
            fout.write(token_tag) # 16 bytes
            fout.write(auth_secret) # 16 bytes
            fout.write(data_nonce) # 8 bytes
            assert fout.tell() == HEADER_LENGTH

            cipher = AES.new(key, AES.MODE_CTR,
                    initial_value=struct.pack('<Q', 0), nonce=data_nonce)

            block = fin.read(cipher.block_size*chunk_size)
            while block:
                data = cipher.encrypt(block)
                fout.write(data)
                yield data
                block = fin.read(cipher.block_size*chunk_size)

    return file_id, token, encrypt

def payload_size(path):
    return os.stat(path).st_size - HEADER_LENGTH

def output_size(path):
    return os.stat(path).st_size + HEADER_LENGTH

def decrypt_generator(filename, download_filename, token, seek=0, end=None, chunk_size=1000000//16):
    with open(filename, 'rb') as fin:
        token_nonce = fin.read(16)
        token_tag = fin.read(16)
        auth_secret = fin.read(16)
        data_nonce = fin.read(8)
        assert fin.tell() == HEADER_LENGTH

    ciphertext = token_b64decode(token)
    token_cipher = AES.new(auth_secret, AES.MODE_GCM, nonce=token_nonce)
    token_cipher.update(download_filename.encode())
    key = token_cipher.decrypt_and_verify(ciphertext, token_tag)

    def generator():
        with open(filename, 'rb') as fin:
            fin.seek(HEADER_LENGTH)
            # Use token cipher's block size assuming the two are the same
            cipher = AES.new(key, AES.MODE_CTR,
                    initial_value=struct.pack('>Q', seek // token_cipher.block_size), nonce=data_nonce)
            fin.seek(seek - seek % cipher.block_size, 1)
            offset = seek % cipher.block_size

            to_send = end - seek + 1 if end else None
            block = fin.read(cipher.block_size*chunk_size)
            while block and (to_send is None or to_send > 0):
                data = cipher.decrypt(block)
                out = data[offset:to_send]
                yield out
                if to_send is not None:
                    to_send -= len(out)
                offset = 0
                block = fin.read(cipher.block_size*chunk_size)
    return generator()

