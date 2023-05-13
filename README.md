# Crypto-Py
Crypto-Py is a command line tool for encrypting and decrypting files and folders using synchronous keys. It is written in Python and can be converted to a .exe file using Pyinstaller.

## Installation
To install Pyinstaller, run the following command in your terminal:

```bash
pip install pyinstaller
To convert the Python file to an executable, run the following command:
```

```bash
pyinstaller --onefile crypto.py
```

## Usage
To use Crypto-Py, run the crypto.exe file followed by the appropriate command line options.

### Options

`--help, -h`: show the help message and exit

`--encrypt, -e`: Encrypt the file or folder

`--decrypt, -d`: Decrypt the file or folder

`--newkey, -n`: Generate a new key for encryption or decryption

`--nooutputkey, -nok`: Do not output the keyfile (DANGER ZONE)

`--key, -k KEY_STRING`: Key string to use for encryption or decryption

`--keyfile, -kf KEY_FILE`: Key file to use for encryption or decryption

`--targets, -t FILE_OR_FOLDER [FILE_OR_FOLDER ...]`: One or more files or directories to encrypt or decrypt (recurses through all sub-directories)

`--include, -in PATERN [PATERN ...]`: Include matching files when target is a directory (ex: -in *.txt *.jpg)

`--exclude, -ex PATERN [PATERN ...]`: Exclude matching files when target is a directory (ex: -ex *.log *.png)

`--backup, -b BACKUP_FILE`: Specify a backup file to store path and encryption/decryption key

`--list, -l`: Only list but do not modify any files

## Examples

Encrypt a file with a new key file:
```bash
# By default, keyfile will be save in the default user directory
crypto.exe --newkey --encrypt --targets /user/data/myfile.txt
```

Use existing key file:
```bash
crypto.exe --encrypt --keyfile keyfile.key --targets /user/data/myfile.txt
```

Decrypt a file or folder:
```bash
# Decrypt myfile.txt
crypto.exe --newkey --keyfile keyfile.key --decrypt --targets /user/data/myfile.txt
# Decrypt directory folder and all files in subfolders
crypto.exe --newkey --keyfile keyfile.key --decrypt --targets /user/data/directory
```

Include only certain file types when encrypting a directory (include only .txt files):
```bash
crypto.exe --encrypt --keyfile keyfile.key --targets /user/data/directory --include *.txt
```

Exclude certain file types when encrypting a directory (exclude all .log files):
```bash
crypto.exe --encrypt --keyfile keyfile.key --targets /user/data/directory --exclude *.log
```

Backup
To backup the paths and encryption/decryption keys for your files, use the --backup option followed by the name of the backup file. For example:
```bash
crypto.exe --encrypt --keyfile /user/bkp/keyfile.key --targets /user/data/myfile.txt --backup /user/bkp/backup.txt
```
This will create a backup file called backup.txt that can be used to restore the encryption/decryption keys for your files.

## Disclaimer
Please use Crypto-Py at your own risk. It is your responsibility to ensure that your files are properly encrypted and that you have backups of your encryption/decryption keys.
