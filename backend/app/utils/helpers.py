import secrets
import string
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
from flask_mail import Message
from flask import current_app

bcrypt = Bcrypt()

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128  # Prevents bcrypt DoS via oversized inputs


def hash_password(password):
    return bcrypt.generate_password_hash(password).decode("utf-8")


def verify_password(password_hash, password):
    return bcrypt.check_password_hash(password_hash, password)


def generate_token(length=32):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_session_token():
    return secrets.token_urlsafe(32)


def is_token_expired(expires_at):
    return datetime.utcnow() > expires_at


def get_token_expiry(seconds):
    return datetime.utcnow() + timedelta(seconds=seconds)


def validate_password_strength(password: str):
    """
    Validate password meets minimum requirements.
    Returns an error message string if invalid, or None if acceptable.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Password must not exceed {MAX_PASSWORD_LENGTH} characters"
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one number"
    return None


def send_email(to, subject, body_html, body_text=None):
    from app import mail

    try:
        msg = Message(
            subject=subject,
            recipients=[to],
            html=body_html,
            body=body_text or body_html,
        )
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Email error: {str(e)}")
        return False


def send_verification_email(user, token):
    url = f"{current_app.config['CORS_ORIGINS']}/verify-email?token={token}"
    subject = f"Verify Email - {current_app.config['APP_NAME']}"
    html = f"""
    <h2>Welcome to {current_app.config['APP_NAME']}!</h2>
    <p>Hi {user.full_name or user.email},</p>
    <p>Please verify your email:</p>
    <a href="{url}" style="background:#4F46E5;color:white;padding:12px 30px;text-decoration:none;border-radius:5px;display:inline-block;">Verify Email</a>
    <p>Or copy: {url}</p>
    <p>Expires in 24 hours.</p>
    """
    return send_email(user.email, subject, html)


def send_password_reset_email(user, token):
    url = f"{current_app.config['CORS_ORIGINS']}/auth/dashboard/reset-password?token={token}"
    subject = f"Reset Password - {current_app.config['APP_NAME']}"
    html = f"""
    <h2>Password Reset Request</h2>
    <p>Hi {user.full_name or user.email},</p>
    <p>Click to reset your password:</p>
    <a href="{url}" style="background:#4F46E5;color:white;padding:12px 30px;text-decoration:none;border-radius:5px;display:inline-block;">Reset Password</a>
    <p>Or copy: {url}</p>
    <p>Expires in 1 hour.</p>
    """
    return send_email(user.email, subject, html)
