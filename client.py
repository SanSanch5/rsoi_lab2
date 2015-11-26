#!/usr/bin/python
from flask import Flask, redirect, request
import requests
import requests.auth

import pprint
application = Flask(__name__)

redirect_uri = r"http://127.0.0.1:5000/auth"


def dump(v):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(v)


@application.route("/")
def index():
    url = 'http://127.0.0.1:8000/oauth/authcode?'
    url += 'response_type=code'
    url += '&client_id=1234'
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

    print("code = " + code)

    auth = requests.auth.HTTPBasicAuth('1234', '5678')
    url = r'http://127.0.0.1:8000/oauth/token'
    #code = "5609fcaf7e7a496341a3c62e1e457a6d"
    params = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': redirect_uri}
    #params = {'grant_type': 'refresh_token', 'refresh_token': "b5391af49652eb235c28fbc09a72601d"}
    response = requests.post(url=url, auth=auth, data=params)

    print(response.text)

    if response.status_code/100 != 2:
        return "request error: " + response.text

    access_token = response.json()["access_token"]
    url = r'http://127.0.0.1:8000/me'
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + access_token}

    response = requests.get(url=url, headers=headers)
    if response.status_code/100 != 2:
        return "request error: " + response.text

    return response.text

if __name__ == "__main__":
    application.run(threaded=True)


