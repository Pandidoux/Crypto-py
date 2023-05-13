
import argparse
import os
import fnmatch
import base64
import string
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_password(length):
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for _ in range(length))
    return password


def generate_key():
    password_bytes = generate_password(20).encode()  # Random string as password
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key


def write_keyfile(key: bytes = None, output_file: string = None):
    if key == None:
        print("No key provided")
        return False
    if output_file == None or not output_file:
        user_directory = os.path.expanduser('~')
        keyfile_path = os.path.join(user_directory, 'key.key')
    else:
        keyfile_path = os.path.abspath(output_file)
    print("Write keyfile: " + keyfile_path)
    try:
        with open(keyfile_path, 'wb') as file:
            file.write(key)
        return True
    except Exception as e:
        print(f"An error occurred while writing {keyfile_path}: {e}")
        return False


def write_backupfile(key: bytes = None, output_file: string = None, targets: list[str] = None, include_filters: list[str] = None, exclude_filters: list[str] = None):
    if key == None:
        print("No key provided")
        return False
    if not targets:
        print("No targets")
        return
    if output_file == None or not output_file:
        user_directory = os.path.expanduser('~')
        backupfile_path = os.path.join(user_directory, 'backup.key')
    else:
        backupfile_path = os.path.abspath(output_file)
    print("Write backup file: " + backupfile_path)
    targets_list = ''
    files_list = ''
    for target_path in targets:
        targets_list += os.path.abspath(target_path) + '\n'
        if os.path.isdir(target_path):  # This target is a directory
            for foldername, subfolders, filenames in os.walk(target_path):
                for filename in filenames:
                    filepath = os.path.join(foldername, filename)
                    if include_filters:  # There is --include filters
                        include_match = any(fnmatch.fnmatch(filename, include_filter) for include_filter in include_filters)
                        if not include_match:
                            continue
                    if exclude_filters:  # There is --exclude filters
                        exclude_match = any(fnmatch.fnmatch(filename, exclude_filter) for exclude_filter in exclude_filters)
                        if exclude_match:
                            continue
                    files_list += os.path.abspath(filepath) + '\n'
        else:  # This target is a file
            files_list += os.path.abspath(target_path) + '\n'
    data_txt = 'Key:\n' + key.decode("utf-8") + '\n\nTargets:\n' + targets_list + '\nFiles list:\n' + files_list
    try:
        with open(backupfile_path, 'w') as file:
            file.write(data_txt)
        return True
    except Exception as e:
        print(f"An error occurred while writing {backupfile_path}: {e}")
        return False


def load_keystring(keystring: string = None):
    if keystring == None:
        return False
    return keystring.encode("utf-8")  # string as bytes


def load_keyfile(keyfile: string = None):
    if keyfile != None:  # keyfile
        if os.path.exists(keyfile):
            return open(keyfile, 'rb').read()
    else:  # No keyfile
        if os.path.exists('key.key'):  # Search default
            return open('key.key', 'rb').read()
        else:
            return False


def encrypt_file(filename: string, key: string, list: bool = False):
    # print('key: ' + key.decode("utf-8") )
    try:
        filepath = os.path.abspath(filename)
        if list:
            print('Not encrypting -> ' + filepath)
            return
        print('Encrypting -> ' + filepath)
        f = Fernet(key)
        with open(filepath, 'rb') as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        with open(filepath, 'wb') as file:
            file.write(encrypted_data)
    except Exception as e:
        print(f"An error occurred while encrypting {filepath}: {e}")


def encrypt_dir(directory: str, key: str, include_filters: list[str] = None, exclude_filters: list[str] = None, list: bool = False):
    for foldername, subfolders, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(foldername, filename)
            if include_filters:  # There is --include filters
                include_match = any(fnmatch.fnmatch(filename, include_filter) for include_filter in include_filters)
                if not include_match:
                    continue
            if exclude_filters:  # There is --exclude filters
                exclude_match = any(fnmatch.fnmatch(filename, exclude_filter) for exclude_filter in exclude_filters)
                if exclude_match:
                    continue
            encrypt_file(filepath, key, list)


def decrypt_file(filename: string, key: string, list: bool = False):
    # print('key: ' + key.decode("utf-8") )
    try:
        filepath = os.path.abspath(filename)
        if list:
            print('Not decrypting -> ' + filepath)
            return
        print('Decrypting -> ' + filepath)
        f = Fernet(key)
        with open(filepath, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = f.decrypt(encrypted_data)
        with open(filepath, 'wb') as file:
            file.write(decrypted_data)
    except Exception as e:
        print(f"An error occurred while decrypting {filepath}: {e}")


def decrypt_dir(directory: str, key: str, include_filters: list[str] = None, exclude_filters: list[str] = None, list: bool = False):
    for foldername, subfolders, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(foldername, filename)
            if include_filters:  # There is --include filters
                include_match = any(fnmatch.fnmatch(filename, include_filter) for include_filter in include_filters)
                if not include_match:
                    continue
            if exclude_filters:  # There is --exclude filters
                exclude_match = any(fnmatch.fnmatch(filename, exclude_filter) for exclude_filter in exclude_filters)
                if exclude_match:
                    continue
            decrypt_file(filepath, key, list)

def main():
    debug = False
    parser = argparse.ArgumentParser(description='A command line tool to encrypt and decrypt files and folders. Can generate a synchronous key for encryption and decryption.')
    parser.add_argument('--encrypt', '-e', action='store_true', help='Encrypt the file or folder')
    parser.add_argument('--decrypt', '-d', action='store_true', help='Decrypt the file or folder')
    parser.add_argument('--newkey', '-n', action='store_true', help='Generate a new key for encryption or decryption')
    parser.add_argument('--nooutputkey', '-nok', action='store_true', help='No output keyfile (DANGER ZONE)')
    parser.add_argument('--key', '-k', metavar="KEY_STRING", type=str, default='', help='Key string to use for encryption or decryption')
    parser.add_argument('--keyfile', '-kf', metavar="KEY_FILE", type=str, default='', help='Key file to use for encryption or decryption')
    parser.add_argument('--targets', '-t', metavar="FILE_OR_FOLDER", nargs='+', required=True, help='One or more files or directories to encrypt or decrypt (recurse through all sub-directories)')
    parser.add_argument('--include', '-in', metavar="PATERN", nargs='+', type=str, default='', help='Include matching files when target is a directory (ex: -in *.txt *.jpg)')
    parser.add_argument('--exclude', '-ex', metavar="PATERN", nargs='+', type=str, default='', help='Exclude matching files when target is a directory (ex: -ex *.log *.png)')
    parser.add_argument('--backup', '-b', metavar="BACKUP_FILE", type=str, default='', help='Specify a backup file to store path and encryption/decryption key')
    parser.add_argument('--list', '-l', action='store_true', help='Only list but do not modify any files')
    args = parser.parse_args()

    # Check args
    user_directory = os.path.expanduser('~')
    default_keyfile = os.path.join(user_directory, 'key.key')
    default_backupfile = os.path.join(user_directory, 'backup.key')

    if args.encrypt:  # --encrypt parameter provided
        if debug: print("--encrypt parameter provided")  #DEBUG
        if not args.targets:  # Error no --targets parameter
            if debug: print("Error no --targets parameter")  #DEBUG
            print('Error: You must specify a parameter --targets')
            print("Stop")
            return

        if args.newkey:  # --newkey parameter provided
            if debug: print("--newkey parameter provided")  #DEBUG
            key = generate_key()  # Create a new key
            if args.nooutputkey:  # --nooutputkey parameter provided
                if debug: print("--nooutputkey parameter provided")  #DEBUG
                print("Do not save key: " + key)
            else:  # no --nooutputkey and no --keyfile
                if debug: print("no --nooutputkey and no --outputkey")  #DEBUG
                if args.keyfile:  # --keyfile parameter provided
                    if debug: print("--keyfile parameter provided")  #DEBUG
                    keyfile = args.keyfile
                else: # no --keyfile parameter provided
                    if debug: print("no --keyfile parameter provided")  #DEBUG
                    keyfile = default_keyfile
                if not write_keyfile(key, keyfile):
                    print("Stop")
                    return
            if args.backup:  # --backup parameter provided
                if debug: print("--backup parameter provided")  #DEBUG
                if debug: print(args.backup)  #DEBUG
                if not write_backupfile(key, args.backup, args.targets, args.include, args.exclude):
                    print("Stop")
                    return

        elif args.key or args.keyfile:  # --key or --keyfile parameter provided
            if debug: print("--key or --keyfile parameter provided")  #DEBUG
            if args.key:  # --key parameter provided
                if debug: print("--key parameter provided")  #DEBUG
                key = load_keystring(args.key)  # Load key
            elif args.keyfile:  # --keyfile parameter provided
                if debug: print("--keyfile parameter provided")  #DEBUG
                key = load_keyfile(args.keyfile)  # Load keyfile

        else:  # no --key and no --keyfile
            if debug: print("no --key and no --keyfile")  #DEBUG
            print("Error: Create a new key (--newkey) or provide a key (--key or --keyfile)")
            print("Stop")
            return

        # For each targets
        if debug: print("For each targets")  #DEBUG
        for target_path in args.targets:
            if os.path.isdir(target_path):  # This target is a directory
                if debug: print("This target is a directory")  #DEBUG
                encrypt_dir(target_path, key, args.include, args.exclude, args.list)  # Encrypt directory
            else:  # This target is a file
                if debug: print("This target is a file")  #DEBUG
                encrypt_file(target_path, key, args.list)  # Encrypt file

    elif args.decrypt:  # --decrypt parameter provided
        if debug: print("--decrypt parameter provided")  #DEBUG
        if not args.targets:  # Error no --targets parameter
            if debug: print("Error no --targets parameter")  #DEBUG
            print('Error: You must specify a parameter --targets')
            return

        if args.key or args.keyfile:# --key or --keyfile parameter provided
            if debug: print("--key or --keyfile parameter provided")  #DEBUG
            if args.key:  # --key parameter provided
                if debug: print("--key parameter provided")  #DEBUG
                key = load_keystring(args.key)  # Load key
            elif args.keyfile:  # --keyfile parameter provided
                if debug: print("--keyfile parameter provided")  #DEBUG
                key = load_keyfile(args.keyfile)  # Load keyfile

        else:  # Else ()
            print('Error: You must specify a parameter --key or --keyfile for decryption')
            print("Stop")
            return

        # For each targets
        if debug: print("For each targets")  #DEBUG
        for target_path in args.targets:
            if os.path.isdir(target_path):  # This target is a directory
                if debug: print("This target is a directory")  #DEBUG
                decrypt_dir(target_path, key, args.include, args.exclude, args.list)  # Encrypt directory
            else:  # This target is a file
                if debug: print("This target is a file")  #DEBUG
                decrypt_file(target_path, key, args.list)  # Encrypt file

    else:
        print('Error: You must specify a parameter --encrypt or --decrypt')
        return

    # Finish
    if args.encrypt:
        print('Encryption complete.')
    else:
        print('Decryption complete.')


if __name__ == '__main__':
    main()
