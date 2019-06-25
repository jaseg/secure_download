#!/usr/bin/env python3

import os

from filecrypt import encrypt_file

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('infile')
    args = parser.parse_args()

    if not os.path.isfile(args.infile):
        print(f'{infile} is not a file or directory, exiting.')
        os.exit(2)

    file_id, token = encrypt_file(args.infile)
    print(f'/{file_id}/{token}/{os.path.basename(args.infile)}')
    
