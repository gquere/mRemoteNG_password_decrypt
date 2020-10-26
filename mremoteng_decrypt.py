#!/usr/bin/env python3
import argparse
import re
import base64
import sys
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad


# DECRYPTION ###################################################################
def gcm_decrypt(data, password):
    salt = data[:16]
    nonce = data[16:32]
    ciphertext = data[32:-16]
    tag = data[-16:]
    # TODO: get these values from the config file
    key = hashlib.pbkdf2_hmac('sha1', password, salt, 1000, dklen=32)   # default values
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(salt)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()
    except ValueError:
        print('MAC tag not valid, this means the master password is wrong or the crypto values aren\'t default')
        exit(1)
    return plaintext

def cbc_decrypt(data, password):
    iv = data[:16]
    ciphertext = data[16:]
    key = hashlib.md5(password).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


# MAIN #########################################################################
parser = argparse.ArgumentParser(description = 'Decrypt mRemoteNG configuration files')
parser.add_argument('config_file', type=str, help='mRemoteNG XML configuration file')
parser.add_argument('-p', '--password', type=str, default='mR3m', help='Optional decryption password')
args = parser.parse_args()

with open(args.config_file, 'r') as f:
    conf = f.read()

mode = re.findall('BlockCipherMode="([^"]*)"', conf)
if not mode:
    mode = 'CBC'            # <1.75 key is md5(password) and encryption is CBC
elif mode[0] == 'GCM':
    mode = 'GCM'            # >=1.75 key is PBKDF2(password) and encryption is GCM
else:
    print('Unknown mode {}, implement it yourself or open a ticket'.format(mode[0]))
    sys.exit(1)

nodes = re.findall('<Node .+/>', conf)
for node in nodes:
    username = re.findall(' Username="([^"]*)"', node)[0]
    hostname = re.findall(' Hostname="([^"]*)"', node)[0]
    data = base64.b64decode(re.findall(' Password="([^ ]*)"', node)[0])
    if data == b'':
        continue

    if mode == 'GCM':
        password = gcm_decrypt(data, args.password.encode())
    elif mode == 'CBC':
        password = cbc_decrypt(data, args.password.encode())

    print('Hostname: {}\nUsername: {}\nPassword: {}\n'.format(hostname, username, password))
