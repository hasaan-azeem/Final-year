import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False

    # JWT
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 7200)))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(seconds=int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', 2592000)))
    JWT_TOKEN_LOCATION = ['headers']
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'

    # CORS
    CORS_ORIGINS = os.getenv('FRONTEND_URL', 'http://localhost:5173')

    # Frontend base URL for OAuth redirects (separate from CORS config)
    FRONTEND_BASE_URL = os.getenv('FRONTEND_URL', 'http://localhost:5173')

    # OAuth
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
    GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI')
    GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
    GITHUB_REDIRECT_URI = os.getenv('GITHUB_REDIRECT_URI')

    # Email
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@yourapp.com')

    # App
    APP_NAME = os.getenv('APP_NAME', 'Auth System')
    VERIFICATION_TOKEN_EXPIRY = int(os.getenv('VERIFICATION_TOKEN_EXPIRY', 86400))
    RESET_TOKEN_EXPIRY = int(os.getenv('RESET_TOKEN_EXPIRY', 3600))

    # Field length limits
    MAX_USERNAME_LENGTH = 50
    MAX_FULL_NAME_LENGTH = 120
    MAX_AVATAR_URL_LENGTH = 500
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True
    # Allow insecure fallbacks in dev only
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-prod')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-change-in-prod')


class ProductionConfig(Config):
    DEBUG = False

    def __init__(self):
        # Crash loudly on startup if critical secrets are missing in production
        missing = []
        for var in ('SECRET_KEY', 'JWT_SECRET_KEY', 'DATABASE_URL'):
            if not os.getenv(var):
                missing.append(var)
        if missing:
            raise EnvironmentError(
                f"Missing required environment variables for production: {', '.join(missing)}"
            )


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}