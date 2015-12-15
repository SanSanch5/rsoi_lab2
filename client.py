#!/usr/bin/python
from flask import Flask, redirect, request
import requests
import requests.auth

application = Flask(__name__)

redirect_uri = r"http://127.0.0.1:8000/auth"
client_id = '7'
secret_key = '6f2d7909690b927fc0aeebdaf8931bb81b2a758dcaa692d781417838eea61102'
access_token = None


@application.route("/")
def index():
    url = 'http://127.0.0.1:5000/oauth/authcode?'
    url += 'response_type=code'
    url += '&client_id=' + client_id
    url += '&redirect_uri=' + redirect_uri
    return redirect(url)


@application.route("/getdebug")
def gdebug():
    print("gdebug")
    return request.query_string


@application.route("/auth")
def auth():
    print(request.query_string)

    code = request.args.get('code')
    if code is None:
        return "bad request"

    auth = requests.auth.HTTPBasicAuth(client_id, secret_key)
    url = r'http://127.0.0.1:5000/oauth/token'
    params = {'grant_type': 'authorization_code',
              'code': code,
              'redirect_uri': redirect_uri,
              'client_id': client_id,
              'client_secret': secret_key,
              }
    response = requests.post(url=url, data=params)

    print(response.text)

    if response.status_code/100 != 2:
        return "request error: " + response.text

    access_token = response.json()["access_token"]
    url = r'http://127.0.0.1:5000/me'
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + access_token}

    response = requests.get(url=url, headers=headers)
    if response.status_code/100 != 2:
        return "request error: " + response.text

    return response.text

if __name__ == "__main__":
    application.run(port=8000, threaded=True)


