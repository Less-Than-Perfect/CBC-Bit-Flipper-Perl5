#!/bin/python3
# Sources: https://palletsprojects.com/p/flask/, https://gist.github.com/forkd/168c9d74b988391e702aac5f4aa69e41, https://flask.palletsprojects.com/en/1.1.x/quickstart/#a-minimal-application

from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import traceback
from flask import Flask, escape, request

app = Flask(__name__) # Figure out why I need this

@app.route("/")
def hello_world():
    msg = "happyerbdayhenryfordhuhlolhappybffforeverandeverman"
    pwd = "personhadasandwitchforbreakfastontheinternettoday202"
    key = md5(pwd.encode('utf8')).digest()

    cte = request.args.get("cte" )
    #pwds = request.args.get("pwd" )
    try:
        if (cte): # decyrpt
            key = md5(pwd.encode('utf8')).digest()
            raw = b64decode(cte)
            cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
            return unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode('utf-8')
        
        else: # encrypt
            iv = "1234567890123456"
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return b64encode(iv + cipher.encrypt(pad(msg.encode('utf-8'), 
                AES.block_size))).decode('utf-8')
    except Exception:
        #return traceback.print_exc() 
        return "bad"
