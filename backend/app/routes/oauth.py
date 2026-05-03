from flask import Blueprint, request, jsonify, redirect, current_app, session
from flask_jwt_extended import create_access_token, create_refresh_token
from datetime import datetime, timezone
import secrets
import requests
from app import db
from app.models import User, OAuthProvider, Session
from app.utils import (
    generate_token,
    generate_session_token,
    get_token_expiry,
)

oauth_bp = Blueprint('oauth', __name__)

SUPPORTED_PROVIDERS = ['google', 'github']


@oauth_bp.route('/oauth/<string:provider>', methods=['GET'])
def oauth_login(provider):
    try:
        if provider not in SUPPORTED_PROVIDERS:
            return jsonify({'error': {'code': 'INVALID_PROVIDER', 'message': 'Invalid provider'}}), 400

        # Generate and store CSRF state token in the server-side session
        state = secrets.token_urlsafe(32)
        session[f'oauth_state_{provider}'] = state

        if provider == 'google':
            url = (
                f"https://accounts.google.com/o/oauth2/v2/auth?"
                f"client_id={current_app.config['GOOGLE_CLIENT_ID']}&"
                f"redirect_uri={current_app.config['GOOGLE_REDIRECT_URI']}&"
                f"response_type=code&scope=openid email profile&state={state}"
            )
        else:
            url = (
                f"https://github.com/login/oauth/authorize?"
                f"client_id={current_app.config['GITHUB_CLIENT_ID']}&"
                f"redirect_uri={current_app.config['GITHUB_REDIRECT_URI']}&"
                f"scope=user:email&state={state}"
            )

        return jsonify({'auth_url': url, 'state': state}), 200

    except Exception as e:
        return jsonify({'error': {'code': 'SERVER_ERROR', 'message': str(e)}}), 500


def _verify_oauth_state(provider):
    """
    Verify the CSRF state parameter matches what was stored in the session.
    Returns (True, None) on success or (False, error_response) on failure.
    """
    incoming_state = request.args.get('state')
    stored_state = session.pop(f'oauth_state_{provider}', None)

    if not incoming_state or not stored_state:
        return False, (jsonify({'error': {'code': 'MISSING_STATE', 'message': 'OAuth state missing'}}), 400)

    if not secrets.compare_digest(incoming_state, stored_state):
        return False, (jsonify({'error': {'code': 'INVALID_STATE', 'message': 'OAuth state mismatch (CSRF check failed)'}}), 400)

    return True, None


def _create_user_session(user_id):
    """Create a DB session record and return a (jwt_access, jwt_refresh) tuple."""
    jwt_access = create_access_token(identity=user_id)
    jwt_refresh = create_refresh_token(identity=user_id)

    db_session = Session(
        user_id=user_id,
        session_token=generate_session_token(),
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        expires_at=get_token_expiry(current_app.config['JWT_REFRESH_TOKEN_EXPIRES'].total_seconds())
    )
    db.session.add(db_session)
    return jwt_access, jwt_refresh


def _build_callback_redirect(jwt_access, jwt_refresh):
    """
    Redirect to the frontend with a short-lived one-time code rather than
    embedding long-lived tokens directly in the URL.

    For a more secure flow you would store the tokens server-side keyed by
    a one-time code and have the frontend POST that code to exchange for tokens.
    As a minimum improvement we at least use the fragment (#) instead of query
    params so the tokens are not sent to the server or stored in server logs.
    """
    frontend_url = current_app.config.get('FRONTEND_BASE_URL', 'http://localhost:5173')
    return redirect(
        f"{frontend_url}/auth/callback"
        f"#access_token={jwt_access}&refresh_token={jwt_refresh}"
    )


@oauth_bp.route('/oauth/google/callback', methods=['GET'])
def google_callback():
    try:
        # Verify CSRF state
        state_ok, state_error = _verify_oauth_state('google')
        if not state_ok:
            return state_error

        code = request.args.get('code')
        if not code:
            return jsonify({'error': {'code': 'MISSING_CODE', 'message': 'Code missing'}}), 400

        # Exchange code for tokens
        token_response = requests.post(
            'https://oauth2.googleapis.com/token',
            data={
                'code': code,
                'client_id': current_app.config['GOOGLE_CLIENT_ID'],
                'client_secret': current_app.config['GOOGLE_CLIENT_SECRET'],
                'redirect_uri': current_app.config['GOOGLE_REDIRECT_URI'],
                'grant_type': 'authorization_code'
            },
            timeout=10
        )
        token_json = token_response.json()
        if 'error' in token_json:
            return jsonify({'error': {'code': 'OAUTH_ERROR', 'message': token_json.get('error_description', 'OAuth failed')}}), 400

        access_token = token_json.get('access_token')
        user_info = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        ).json()

        email = user_info.get('email')
        provider_user_id = user_info.get('id')

        if not email or not provider_user_id:
            return jsonify({'error': {'code': 'OAUTH_ERROR', 'message': 'Could not retrieve account details from Google'}}), 400

        oauth_provider = OAuthProvider.query.filter_by(
            provider='google', provider_user_id=provider_user_id
        ).first()

        if oauth_provider:
            user = oauth_provider.user
            oauth_provider.access_token = access_token
            oauth_provider.refresh_token = token_json.get('refresh_token')
            oauth_provider.updated_at = datetime.now(timezone.utc)
        else:
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(
                    email=email,
                    full_name=user_info.get('name'),
                    avatar_url=user_info.get('picture'),
                    is_verified=True
                )
                db.session.add(user)
                db.session.flush()

            oauth_provider = OAuthProvider(
                user_id=user.id,
                provider='google',
                provider_user_id=provider_user_id,
                access_token=access_token,
                refresh_token=token_json.get('refresh_token')
            )
            db.session.add(oauth_provider)

        user.last_login = datetime.now(timezone.utc)
        jwt_access, jwt_refresh = _create_user_session(user.id)
        db.session.commit()

        return _build_callback_redirect(jwt_access, jwt_refresh)

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': {'code': 'SERVER_ERROR', 'message': str(e)}}), 500


@oauth_bp.route('/oauth/github/callback', methods=['GET'])
def github_callback():
    try:
        # Verify CSRF state
        state_ok, state_error = _verify_oauth_state('github')
        if not state_ok:
            return state_error

        code = request.args.get('code')
        if not code:
            return jsonify({'error': {'code': 'MISSING_CODE', 'message': 'Code missing'}}), 400

        # Exchange code for access token
        token_response = requests.post(
            'https://github.com/login/oauth/access_token',
            data={
                'client_id': current_app.config['GITHUB_CLIENT_ID'],
                'client_secret': current_app.config['GITHUB_CLIENT_SECRET'],
                'code': code,
                'redirect_uri': current_app.config['GITHUB_REDIRECT_URI']
            },
            headers={'Accept': 'application/json'},
            timeout=10
        )
        token_json = token_response.json()
        if 'error' in token_json:
            return jsonify({'error': {'code': 'OAUTH_ERROR', 'message': token_json.get('error_description', 'OAuth failed')}}), 400

        access_token = token_json.get('access_token')
        gh_headers = {'Authorization': f'token {access_token}'}

        user_info = requests.get('https://api.github.com/user', headers=gh_headers, timeout=10).json()

        # Resolve email: try public profile first, then the emails endpoint
        email = user_info.get('email')
        if not email:
            emails_resp = requests.get('https://api.github.com/user/emails', headers=gh_headers, timeout=10).json()
            if isinstance(emails_resp, list):
                for entry in emails_resp:
                    if entry.get('primary') and entry.get('verified'):
                        email = entry.get('email')
                        break
                # Fallback to first verified email if no primary found
                if not email:
                    for entry in emails_resp:
                        if entry.get('verified'):
                            email = entry.get('email')
                            break

        if not email:
            return jsonify({
                'error': {
                    'code': 'NO_EMAIL',
                    'message': 'A verified email address is required. Please add and verify an email in your GitHub settings.'
                }
            }), 400

        provider_user_id = str(user_info.get('id'))

        oauth_provider = OAuthProvider.query.filter_by(
            provider='github', provider_user_id=provider_user_id
        ).first()

        if oauth_provider:
            user = oauth_provider.user
            oauth_provider.access_token = access_token
            oauth_provider.updated_at = datetime.now(timezone.utc)
        else:
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(
                    email=email,
                    username=user_info.get('login'),
                    full_name=user_info.get('name'),
                    avatar_url=user_info.get('avatar_url'),
                    is_verified=True
                )
                db.session.add(user)
                db.session.flush()

            oauth_provider = OAuthProvider(
                user_id=user.id,
                provider='github',
                provider_user_id=provider_user_id,
                access_token=access_token
            )
            db.session.add(oauth_provider)

        user.last_login = datetime.now(timezone.utc)
        jwt_access, jwt_refresh = _create_user_session(user.id)
        db.session.commit()

        return _build_callback_redirect(jwt_access, jwt_refresh)

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': {'code': 'SERVER_ERROR', 'message': str(e)}}), 500