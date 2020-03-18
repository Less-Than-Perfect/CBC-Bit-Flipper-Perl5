#!/usr/bin/python3
# Sources: https://palletsprojects.com/p/flask/, https://gist.github.com/forkd/168c9d74b988391e702aac5f4aa69e41, https://flask.palletsprojects.com/en/1.1.x/quickstart/#a-minimal-application
import cryptME

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
import gc


app = Flask(__name__) # Figure out why I need this

@app.route("/")
def hello_world():
    cte = request.args.get("cte" )
    me = cryptME.myMAN()
    if (cte):
        try:
            return me.decrypt(cte)
        except:
            return "bad"
    else:
        return me.encrypt()
        

if __name__ == '__main__':
    app.run(debug=False)