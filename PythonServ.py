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
from sys import stderr
import logging

app = Flask(__name__) # Figure out why I need this

@app.route("/")
def hello_world():
    msg = "ilisgingspariesuranizestanedgelishearionzarriceaa5"
    pwd = "irdeitusablidessesssewallutordandixialstrildippor3"
    key = md5(pwd.encode('utf8')).digest()

    cte = request.args.get("cte" )
    if (cte):
        cte = urllib.parse.unquote(cte)
    #pwds = request.args.get("pwd" )

    if (cte): # decyrpt
        key = md5(pwd.encode('utf8')).digest()
        raw = b64decode(cte)
        cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
        print (cipher.decrypt(raw[AES.block_size:]))
        rValue = unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode('utf-8')
        return rValue
        
    else: # encrypt
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        lolValue = b64encode(iv + cipher.encrypt(pad(msg.encode('utf-8'),  AES.block_size))).decode('utf-8')
        return urllib.parse.quote_plus(lolValue)
        

if __name__ == '__main__':
    app.run(debug=True)
