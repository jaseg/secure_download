#!/usr/bin/env python3

if __name__ == '__main__':
    import os
    import configparser
    import argparse

    from tqdm import tqdm

    from filecrypt import generate_keys, payload_size

    parser = argparse.ArgumentParser(description='Filecrypt secure file download encryption tool.'
            'Encrypts a file for use with the filecrypt server, and output the generated download link.')
    parser.add_argument('infile')
    parser.add_argument('-c', '--config', default=None, help='Config file location (default; $XDG_CONFIG_HOME/filecrypt.conf)')
    parser.add_argument('-b', '--base-url', default=None, help='Base URL for link (also as config option)')
    parser.add_argument('-f', '--filename', default=None, help='Download filename (default: Same as input filename)')
    parser.add_argument('-q', '--no-progress', action='store_true', help='Hide progress bar')
    parser.add_argument('-p', '--progress', action='store_true', help='Show progress bar (default, also as config option)')
    args = parser.parse_args()

    progress = (not args.no_progress) or args.progress
    config_path = args.config or os.environ.get('XDG_CONFIG_HOME', os.environ.get('HOME') + '/.config') + '/filecrypt.conf'
    base_url = args.base_url
    if os.path.isfile(config_path):
        with open(config_path) as f:
            config = configparser.ConfigParser(defaults={'url_base': ''})
            config.read_string('[DEFAULT]\n'+f.read()) # doesn't parse simple key=value file by default m(

            if base_url is None:
                base_url = config.get('DEFAULT', 'base_url', fallback='').rstrip('/')
            if not (args.no_progress or args.progress):
                progress = config.getboolean('DEFAULT', 'progress', fallback=True)

    if not os.path.isfile(args.infile):
        print(f'{infile} is not a file or directory, exiting.')
        os.exit(2)

    download_filename = args.filename or os.path.basename(args.infile)

    file_id, token, encrypt = generate_keys(download_filename)
    print(f'{base_url}/{file_id}/{token}/{download_filename}')

    if progress:
        with tqdm(total=payload_size(args.infile), unit='B', unit_scale=True) as pbar:
            for progress in encrypt(args.infile):
                pbar.update(progress)
    else:
        for _progress in encrypt(args.infile):
            pass
    
