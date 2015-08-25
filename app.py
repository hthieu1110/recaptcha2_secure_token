# -*- coding: utf-8 -*-
import requests
from os import urandom
import json
from hashlib import sha1
from Crypto.Cipher import AES
from uuid import uuid4
from time import time
from base64 import urlsafe_b64encode

from flask import Flask, render_template, request, jsonify

app = Flask(__name__, template_folder='')


# Get key pair from: https://www.google.com/recaptcha/admin#list
PRIVATE_KEY = '---'
PUBLIC_KEY = '---'
CAPTCHA_API_URL = 'https://www.google.com/recaptcha/api/siteverify'

# Tool functions for padding, unpadding string
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[0:-ord(s[-1])]


def generate_stoken():
    # Build json token
    json_token = json.dumps({
        "session_id": str(uuid4()),
        "ts_ms": str(time())
    })

    # Encrypt json token by AES/CBC/PKCS5Padding
    # Key used for AES crypto
    aes_key = sha1(PRIVATE_KEY).hexdigest()[:BLOCK_SIZE]

    # AES use block so we need to pad input for having valid block
    padded = pad(json_token)

    # Random string, use for AES in mode CBC
    # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
    iv = urandom(BLOCK_SIZE)

    # Encrypt padded string by AES cypto
    encrypted_str = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(padded)

    # Generate base64 string with urlsafe mode
    base64_str = urlsafe_b64encode(unpad(encrypted_str))
    return base64_str


@app.route('/')
def index():
    stoken = generate_stoken()
    return render_template('index.html', **{'stoken': stoken, 'public_key': PUBLIC_KEY})


@app.route('/check', methods=['POST'])
def check():
    payload = {
        'secret': PRIVATE_KEY,
        'remoteip': str(request.remote_addr),
        'response': request.form.get('g-recaptcha-response')
    }
    captcha_resp = requests.post(CAPTCHA_API_URL, payload)
    result = json.loads(captcha_resp.content)
    return jsonify(result)

app.run('localhost', port=1984, debug=True)


