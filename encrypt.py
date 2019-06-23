#!/usr/bin/env python3

import secrets
from Cryptodome.Cipher import AES
import base64
import struct
import subprocess
import binascii

def _pad(data, blocksize):
    return (data + b'\x80' + b'\x00'*blocksize)[:blocksize]

def _unpad(data):
    data = data.rstrip(b'\0')
    if data[-1] == 0x80:
        return data[:-1]
    else:
        raise ValueError('Invalid padding!')

def encrypt_file(filename_in):
    file_id = secrets.token_urlsafe(22)
    auth_secret = secrets.token_bytes(16)
    key = secrets.token_bytes(16)
    cipher_nonce = secrets.token_bytes(8)

    token_cipher = AES.new(auth_secret, AES.MODE_GCM)
    ciphertext, token_tag = token_cipher.encrypt_and_digest(key)
    token = base64.b64encode(ciphertext)

    with open(filename_in, 'rb', buffering=8192) as fin, open(f'{file_id}.enc', 'wb', buffering=8192) as fout:
        fout.write(token_cipher.nonce) # 16 bytes
        fout.write(token_tag) # 16 bytes
        fout.write(auth_secret) # 16 bytes
        fout.write(cipher_nonce) # 8 bytes

        subprocess.check_call(['openssl', 'enc', '-aes-128-ctr',
            '-K', binascii.hexlify(key),
            '-iv', binascii.hexlify(cipher_nonce + '\0'*8)

        data = fin.read(cipher.block_size) or None
        while data is not None:
            next_data = fin.read(cipher.block_size) or None
            if not next_data: # padding required
                if len(data) == cipher.block_size:
                    next_data = b''
                else:
                    data = _pad(data, cipher.block_size)
            fout.write(cipher.encrypt(data))
            data = next_data

    return file_id, token

def decrypt_generator(file_id, token, seek=0):

    with open(f'{file_id}.enc', 'rb', buffering=8192) as fin:
        token_nonce = fin.read(16)
        token_tag = fin.read(16)
        auth_secret = fin.read(16)
        data_nonce = fin.read(8)

        ciphertext = base64.b64decode(token)
        token_cipher = AES.new(auth_secret, AES.MODE_GCM, nonce=token_nonce)
        key = token_cipher.decrypt_and_verify(ciphertext, token_tag)

        # Use token cipher's block size assuming the two are the same
        cipher = AES.new(key, AES.MODE_CTR,
                initial_value=struct.pack('<Q', seek // token_cipher.block_size), nonce=data_nonce)
        fin.seek(seek - seek % cipher.block_size, 1)
        offset = seek % cipher.block_size

        next_block = fin.read(cipher.block_size)
        while next_block:
            block = next_block
            next_block = fin.read(cipher.block_size)
            data = cipher.decrypt(block)

            if not next_block: # remove padding
                data = _unpad(data)
            
            yield data[offset:]
            offset = 0

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('infile')
    parser.add_argument('outfile')
    args = parser.parse_args()

    file_id, token = encrypt_file(args.infile)
    
    with open(args.outfile, 'wb', buffering=8192) as fout:
        for data in decrypt_generator(file_id, token):
            fout.write(data)

