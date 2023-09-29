#!/usr/bin/env python
import sys
import os
import io
import json
import random
import logging
import yaml
import qrcode
import urllib.parse

from threading import Timer
from datetime import timedelta

from flask import Flask, Response, request, Markup, session, render_template
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession
from flask_session import Session

logging.getLogger().setLevel(logging.DEBUG)
logging.getLogger('flask_pyoidc').setLevel(logging.ERROR)
logging.getLogger('oic').setLevel(logging.ERROR)
logging.getLogger('jwkest').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)
logging.getLogger('werkzeug').setLevel(logging.ERROR)

app = Flask(__name__, template_folder='templates', static_folder='static')

with open(sys.argv[1]) as f:
    config = yaml.safe_load(f)

appConfig = {
    "OIDC_REDIRECT_URI": config['oidc']['redirect_uri'],
    "SESSION_PERMANENT": False,
    "SESSION_TYPE": "filesystem",
    "PERMANENT_SESSION_LIFETIME": timedelta(hours=8),
    "SESSION_COOKIE_SAMESITE": "Lax",
}

app.config.from_mapping(appConfig)
Session(app)

oidc_enabled = config['oidc']['enabled']

if oidc_enabled:
    client_metadata = ClientMetadata(
        client_id=config['oidc']['client_id'],
        client_secret=config['oidc']['client_secret'])

    provider_config = ProviderConfiguration(
        issuer=config['oidc']['issuer'],
        client_metadata=client_metadata)

    authzn = OIDCAuthentication({'pam-weblogin': provider_config}, app)
else:
    authzn = None

timeout = config['timeout']

auths = {}
cached = {}

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
numbers = '1234567890'


def pop_auth(session_id):
    logging.debug(f"pop auth {session_id}")
    auths.pop(session_id, None)


def pop_cached(user_id):
    logging.debug(f"pop cached {user_id}")
    cached.pop(user_id, None)


def session_id(length=8):
    return ''.join([str(random.choice(chars)) for i in range(length)])


def code(length=4):
    return ''.join([str(random.choice(numbers)) for i in range(length)])


def authorized(headers):
    auth = headers.get("Authorization")
    if "Bearer" in auth:
        return True
    else:
        return False


def create_qr(url):
    qr = qrcode.QRCode()
    qr.add_data(url)

    f = io.StringIO()
    qr.print_ascii(out=f, invert=True)
    f.seek(0)

    return f.read()

def add_token(url, token):
    # Parse the URL into its components
    url_parts = urllib.parse.urlparse(url)
    # Parse the query string into a dictionary
    query_dict = urllib.parse.parse_qs(url_parts.query)
    # Add the token to the dictionary
    query_dict['token'] = token
    # Encode the dictionary back into a query string
    query_string = urllib.parse.urlencode(query_dict, doseq=True)
    # Replace the query component of the URL with the new query string
    new_url_parts = url_parts._replace(query=query_string)
    # Return the modified URL as a string
    return urllib.parse.urlunparse(new_url_parts)

@app.route('/pam-weblogin/ssh_keys', methods=['GET'])
def ssh():
    logging.debug('/pam-weblogin/ssh_keys <-')
    response = Response(status=200)
    keys = [
        'ssh-rsa AAAA... example@server',
    ]
    response.data = json.dumps(keys)
    return response


@app.route('/pam-weblogin/start', methods=['POST'])
def start():
    data = json.loads(request.data)
    logging.debug(f"/pam-weblogin/start\n <- {data}")
    if not authorized(request.headers):
        response = Response(status=404)
        msg = {'error': True, 'message': 'Unauthorized'}
        response.data = json.dumps(msg)
        logging.debug(f" -> {msg}")
        return response

    user_id = data.get('user_id')
    attribute = data.get('attribute')
    cache_duration = data.get('cache_duration', 0)
    redirect = data.get('redirect', "")
    auth_only = data.get('auth_only', "false")
    auth_only = (auth_only == "true");
    
    new_session_id = session_id()
    url = os.environ.get("URL", config['url']).rstrip('/')
    qr_code = create_qr(url)
    cache = cached.get(user_id, False)
    displayname = user_id or 'weblogin'
    auths[new_session_id] = {
        'session_id': new_session_id,
        'challenge_url': f'{url}/pam-weblogin/login/{new_session_id}',
        'challenge': f'Hello {displayname}. To continue, '
                     f'visit {url}/pam-weblogin/login/{new_session_id} and enter verification code\n\n'
                     f'{qr_code}',
        'cached': cache,
        'info': 'Login was cached' if cache else 'Sign in'
    }

    new_code = code()
    auths[new_session_id]['user_id'] = user_id
    auths[new_session_id]['attribute'] = attribute
    auths[new_session_id]['code'] = new_code
    auths[new_session_id]['cache_duration'] = cache_duration
    auths[new_session_id]['redirect'] = redirect
    auths[new_session_id]['auth_only'] = auth_only
    Timer(timeout, pop_auth, [new_session_id]).start()
    
    response = Response(status=201)
    response.headers['Content-Type'] = "application/json"
    response.data = json.dumps(auths[new_session_id])

    logging.debug(f' -> {response.data.decode()}\n'
                  f'  code: {new_code}')

    return response


@app.route('/pam-weblogin/check-pin', methods=['POST'])
def check_pin():
    if not authorized(request.headers):
        response = Response(status=401)
        msg = {'error': True, 'message': 'Unauthorized'}
        response.data = json.dumps(msg)
        logging.debug(f" -> {msg}")
        return response

    data = json.loads(request.data)
    session_id = data.get('session_id')
    rcode = data.get('pin')

    this_auth = auths.get(session_id)
    if this_auth:
        user_id = this_auth.get('user_id')
        attribute = this_auth.get('attribute')
        matching_attribute = this_auth.get('matching_attribute')
        code = this_auth.get('code')
        cache_duration = this_auth.get('cache_duration')
        if rcode == code:
            reply = {
                'result': 'SUCCESS',
                'username': user_id,
                'matching_attribute': matching_attribute,
                'info': f'Authenticated on attribute {attribute}'
            }
            cached[user_id] = True
            pop_auth(session_id)
            Timer(int(cache_duration), pop_cached, [user_id]).start()
        else:
            reply = {
                'result': 'FAIL',
                'info': 'Verification failed'
            }
    else:
        reply = {
            'result': 'TIMEOUT',
            'info': 'Authentication failed'
        }

    response = Response(status=201)
    response.headers['Content-Type'] = "application/json"
    response.data = json.dumps(reply)

    logging.debug(f'/pam-weblogin/check-pin <- {data}\n -> {response.data.decode()}')

    return response


def __login(session_id):
    logging.info(f'/pam-weblogin/login/{session_id}')

    try:
        user_session = UserSession(session)
        userinfo = user_session.userinfo
    except Exception:
        userinfo = {}

    this_auth = auths.get(session_id)
    if this_auth:
        request.data
        user_id = this_auth.get('user_id')
        attribute_id = userinfo.get(this_auth.get('attribute'))
        auth_only = this_auth.get('auth_only')
        logging.info(f"user_id: {user_id}, attribute_id: {attribute_id}")
        if (user_id
            and attribute_id
            and (auth_only or user_id in attribute_id)
            or not oidc_enabled):
            user_id = Markup.escape(user_id)
            attribute_id = Markup.escape(attribute_id)
            code = this_auth['code']
            code = Markup.escape(code)
            
            auths[session_id]['matching_attribute'] = attribute_id
            
            redirect = this_auth.get('redirect')
            if (redirect != ""):
                response = Response(status=302)
                # Redirect the client back with the code given as a ?token=
                response.headers['Location'] = add_token(redirect, code)
                return response
                
            message = f"<h1>SSH request</h1>\n"
            message += f"for session {session_id}/{user_id}<br>\n"
            message += f"{attribute_id} successfully authenticated<br>\n"
            message += f"Verification code: {code}<br><br>\n"
            message += "<i>This window may be closed</i>\n"
        else:
            message = f"user_id {user_id} not found\n"
    else:
        message = "session_id not found\n"

    response = render_template('login.j2', message=message)

    return response


if isinstance(authzn, OIDCAuthentication):
    __login = authzn.oidc_auth('pam-weblogin')(__login)


@app.route('/pam-weblogin/login/<session_id>', methods=['GET'])
def login(session_id):
    return __login(session_id)


if __name__ == "__main__":
    app.run(host=config['host'], port=config['port'])
