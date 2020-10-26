Decrypt mRemoteNG passwords
===========================

Decrypt mRemoteNG configuration files, old and new format.
More info [here](https://errno.fr/mRemoteNG_decrypt.md).

Usage
-----
```
usage: mremoteng_decrypt.py [-h] [-p PASSWORD] config_file

Decrypt mRemoteNG configuration files

positional arguments:
  config_file                       mRemoteNG XML configuration file

optional arguments:
  -p PASSWORD, --password PASSWORD  Optional decryption password
```

Example:
```
mremoteng_decrypt.py ./mRemoteNG-1.70/confCons.xml
```
