#!/usr/bin/python3
# Audit imports
from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import traceback
import urllib.parse
import sys
import logging
import gc
#

class myMAN():
    def __init__(self):
        self.msg = "nticssellusionysitionederboxswinvautionsimatonsagiustoustofseli"
        self.pwd = "tusablidessesasdoaud0923738130-ejxkmasxi382909cj382dy3j92ssa"
        self.key = md5(self.pwd.encode('utf8')).digest()

    def decrypt (self, cte):
        cte = urllib.parse.unquote(cte)
        raw = b64decode(cte)
        cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        temp = cipher.decrypt(raw[AES.block_size:])
        print (temp)
        return unpad(temp, AES.block_size)


    def encrypt(self):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        lolValue = b64encode(iv + cipher.encrypt(pad(self.msg.encode('utf-8'),  AES.block_size)))
        return urllib.parse.quote_plus(lolValue)
