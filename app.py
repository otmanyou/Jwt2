from flask import Flask, request, jsonify
import jwt
import requests
from protobuf_decoder.protobuf_decoder import Parser
from datetime import datetime
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid):
    try:
        now = datetime.now()
        now = str(now)[:len(str(now)) - 7]
        data = bytes.fromhex('1a13323032342d31322d...')  # استخدم الداتا الكاملة
        data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB47',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjEi...',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        URL = "https://loginbp.common.ggbluefox.com/MajorLogin"
        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            BASE64_TOKEN = RESPONSE.text.split(".")[0] + "." + RESPONSE.text.split(".")[1] + "." + RESPONSE.text.split(".")[2][:44]
            return BASE64_TOKEN
        return False
    except Exception as e:
        return False

@app.route('/check_token', methods=['GET'])
def check_token():
    try:
        uid = request.args.get('uid')
        password = request.args.get('password')
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }
        data = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "",
            "client_id": "100067",
        }
        response = requests.post(url, headers=headers, data=data)
        response_data = response.json()
        NEW_ACCESS_TOKEN = response_data.get('access_token')
        NEW_OPEN_ID = response_data.get('open_id')
        if not NEW_ACCESS_TOKEN or not NEW_OPEN_ID:
            return jsonify({"status": "failure", "message": "Invalid credentials"})
        
        OLD_ACCESS_TOKEN = "1f164b149a618e3e0c77232d08913765c7b11c3d86ee21bb541e797cd114951d"
        OLD_OPEN_ID = "e32fabfd33fd3e5d0c19547b13727cb9"
        
        token = TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid)
        if token:
            return jsonify({"status": "success", "token": token})
        else:
            return jsonify({"status": "failure", "message": "Failed to generate token"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

def handler(event, context):
    return app(event, context)
