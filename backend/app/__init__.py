from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_mail import Mail
from app.config import config
import os

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
mail = Mail()

def create_app(config_name=None):
    app = Flask(__name__)
    
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    
    app.config.from_object(config[config_name])
    
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    mail.init_app(app)
    
    # CORS configuration - allow frontend to make requests
    CORS(app, 
         resources={r"/api/*": {"origins": app.config['CORS_ORIGINS']}},
         supports_credentials=True,
         allow_headers=['Content-Type', 'Authorization', 'X-Session-Token'],
         expose_headers=['Content-Type', 'Authorization'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    
    # Handle preflight OPTIONS requests
    @app.before_request
    def handle_preflight():
        from flask import request
        if request.method == "OPTIONS":
            response = app.make_default_options_response()
            response.headers['Access-Control-Allow-Origin'] = app.config['CORS_ORIGINS']
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Session-Token'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response
    
    # Only import auth and user routes - no dashboard needed
    from app.routes import auth_bp, oauth_bp, user_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(oauth_bp, url_prefix='/api/auth')
    app.register_blueprint(user_bp, url_prefix='/api/users')
    
    @app.errorhandler(404)
    def not_found(error):
        return {'error': {'code': 'NOT_FOUND', 'message': 'Not found'}}, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return {'error': {'code': 'SERVER_ERROR', 'message': 'Server error'}}, 500
    
    @app.route('/health')
    def health():
        return {'status': 'healthy'}, 200
    
    @app.route('/')
    def index():
        return {
            'message': 'Auth API',
            'version': '1.0.0',
            'endpoints': {
                'auth': '/api/auth',
                'users': '/api/users'
            }
        }, 200
    
    return app