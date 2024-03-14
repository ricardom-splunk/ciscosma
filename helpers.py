import base64
import requests
import json


def b64_encode(s):
    s_utf8 = s.encode('utf-8')
    base64_encoded = base64.b64encode(s_utf8)
    return base64_encoded.decode('utf-8')


def get_jwt_token(url, username, password):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    payload = json.dumps({
      "data": {
        "userName": b64_encode(username),
        "passphrase": b64_encode(password)
      }
    })

    response = requests.request("POST", url, headers=headers, data=payload)
    jwt_token = response.json().get('data').get('jwtToken')
    return jwt_token
