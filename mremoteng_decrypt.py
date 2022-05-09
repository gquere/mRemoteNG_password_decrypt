#!/usr/bin/env python3
import argparse
import csv
import re
import base64
import sys
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad


# DECRYPTION ###################################################################
def decrypt(mode, data, password):
    if (mode == 'CBC'):
        return cbc_decrypt(data, password)
    if (mode == 'GCM'):
        return gcm_decrypt(data, password)
    raise ValueError(f'unkown mode {mode}') ;

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


# OUTPUT #######################################################################
def print_output(name, hostname, username, password):
    if args.csv :
        csv_out.writerow((name, hostname, username, password))
    else:
        print('Name: {}\nHostname: {}\nUsername: {}\nPassword: {}\n'.format(name, hostname, username, password))

# MAIN #########################################################################
parser = argparse.ArgumentParser(description = 'Decrypt mRemoteNG configuration files')
parser.add_argument('config_file', type=str, help='mRemoteNG XML configuration file')
parser.add_argument('-p', '--password', type=str, default='mR3m', help='Optional decryption password')
parser.add_argument('--csv', default=False, action='store_true', help ='Output CSV format')
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

# Extract and decrypt file data if FullFileEncryption is true
full_encryption = re.findall('FullFileEncryption="([^"]*)"', conf)

if full_encryption and (full_encryption[0] == 'true'):
    cypher=base64.b64decode(re.findall('<.*>(.+)</mrng:Connections>', conf)[0]) 
    conf=decrypt(mode, cypher, args.password.encode())

nodes = re.findall('<Node .+?>', conf)

if args.csv :
    csv_out = csv.writer(sys.stdout, dialect='unix', quoting=csv.QUOTE_MINIMAL)
    csv_out.writerow(('Name', 'Hostname', 'Username', 'Password'))

for node in nodes:
    name = re.findall(' Name="([^"]*)"', node)[0]
    username = re.findall(' Username="([^"]*)"', node)[0]
    hostname = re.findall(' Hostname="([^"]*)"', node)[0]
    data = base64.b64decode(re.findall(' Password="([^ ]*)"', node)[0])
    password=""
    if data != b'':
        password=decrypt(mode, data, args.password.encode())

    print_output(name, hostname, username, password)

