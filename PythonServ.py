#!/usr/bin/python3
# Sources: https://palletsprojects.com/p/flask/, https://gist.github.com/forkd/168c9d74b988391e702aac5f4aa69e41, https://flask.palletsprojects.com/en/1.1.x/quickstart/#a-minimal-application

from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import traceback
from flask import Flask, escape, request
import urllib.parse
import sys
import logging

app = Flask(__name__) # Figure out why I need this

@app.route("/")
def hello_world():
    msg = "nticssellusionysitionederboxswinvautionsimatonsagiustoustofseli"
    pwd = "tusablidessesasdoaud0923738130-ejxkmasxi382909cj382dy3j92ssa"
    key = md5(pwd.encode('utf8')).digest()

    cte = request.args.get("cte" )
    #pwds = request.args.get("pwd"   )

    if (cte): # decyrpt
        cte = urllib.parse.unquote(cte)
        raw = b64decode(cte)
        cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
        temp = cipher.decrypt(raw[AES.block_size:])
        print (temp)
        return unpad(temp, AES.block_size)
        
    else: # encrypt
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        lolValue = b64encode(iv + cipher.encrypt(pad(msg.encode('utf-8'),  AES.block_size)))
        return urllib.parse.quote_plus(lolValue)
        

if __name__ == '__main__':
    app.run(debug=True)