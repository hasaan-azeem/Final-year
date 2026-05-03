from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
)
from datetime import datetime, timezone
from app import db
from app.models import User, Session, EmailVerification
from app.utils import (
    hash_password,
    verify_password,
    generate_token,
    generate_session_token,
    get_token_expiry,
    is_token_expired,
    send_verification_email,
    validate_password_strength,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Request body required",
                        }
                    }
                ),
                400,
            )

        email = data.get("email", "").strip().lower()
        password = data.get("password", "")
        username = data.get("username", "").strip()
        full_name = data.get("full_name", "").strip()

        if not email or not password:
            return (
                jsonify(
                    {
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Email and password required",
                        }
                    }
                ),
                400,
            )

        # Password strength validation
        password_error = validate_password_strength(password)
        if password_error:
            return (
                jsonify(
                    {"error": {"code": "WEAK_PASSWORD", "message": password_error}}
                ),
                400,
            )

        # Field length validation
        max_username = current_app.config.get("MAX_USERNAME_LENGTH", 50)
        max_full_name = current_app.config.get("MAX_FULL_NAME_LENGTH", 120)
        if username and len(username) > max_username:
            return (
                jsonify(
                    {
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": f"Username too long (max {max_username} chars)",
                        }
                    }
                ),
                400,
            )
        if full_name and len(full_name) > max_full_name:
            return (
                jsonify(
                    {
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": f"Full name too long (max {max_full_name} chars)",
                        }
                    }
                ),
                400,
            )

        if User.query.filter_by(email=email).first():
            return (
                jsonify(
                    {
                        "error": {
                            "code": "USER_EXISTS",
                            "message": "Email already exists",
                        }
                    }
                ),
                409,
            )

        if username and User.query.filter_by(username=username).first():
            return (
                jsonify(
                    {"error": {"code": "USERNAME_TAKEN", "message": "Username taken"}}
                ),
                409,
            )

        user = User(
            email=email,
            username=username or None,
            password_hash=hash_password(password),
            full_name=full_name or None,
            is_verified=False,
        )
        db.session.add(user)
        db.session.flush()  # Populate user.id without committing yet

        token = generate_token(32)
        verification = EmailVerification(
            user_id=user.id,
            verification_token=token,
            expires_at=get_token_expiry(
                current_app.config["VERIFICATION_TOKEN_EXPIRY"]
            ),
        )
        db.session.add(verification)

        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        session = Session(
            user_id=user.id,
            session_token=generate_session_token(),
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            expires_at=get_token_expiry(
                current_app.config["JWT_REFRESH_TOKEN_EXPIRES"].total_seconds()
            ),
        )
        db.session.add(session)

        # Single commit for the entire registration
        db.session.commit()

        send_verification_email(user, token)

        return (
            jsonify(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "Bearer",
                    "expires_in": current_app.config[
                        "JWT_ACCESS_TOKEN_EXPIRES"
                    ].total_seconds(),
                    "user": user.to_dict(),
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500


@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Request body required",
                        }
                    }
                ),
                400,
            )

        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        if not email or not password:
            return (
                jsonify(
                    {
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Email and password required",
                        }
                    }
                ),
                400,
            )

        user = User.query.filter_by(email=email).first()

        # Unified error to prevent user enumeration
        if (
            not user
            or not user.password_hash
            or not verify_password(user.password_hash, password)
        ):
            return (
                jsonify(
                    {
                        "error": {
                            "code": "INVALID_CREDENTIALS",
                            "message": "Invalid credentials",
                        }
                    }
                ),
                401,
            )

        if not user.is_active:
            return (
                jsonify(
                    {
                        "error": {
                            "code": "ACCOUNT_DISABLED",
                            "message": "Account disabled",
                        }
                    }
                ),
                403,
            )

        user.last_login = datetime.now(timezone.utc)

        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        session = Session(
            user_id=user.id,
            session_token=generate_session_token(),
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            expires_at=get_token_expiry(
                current_app.config["JWT_REFRESH_TOKEN_EXPIRES"].total_seconds()
            ),
        )
        db.session.add(session)
        db.session.commit()

        return (
            jsonify(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "Bearer",
                    "expires_in": current_app.config[
                        "JWT_ACCESS_TOKEN_EXPIRES"
                    ].total_seconds(),
                    "user": user.to_dict(),
                }
            ),
            200,
        )

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_me():
    """Get current authenticated user"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user:
            return (
                jsonify(
                    {"error": {"code": "USER_NOT_FOUND", "message": "User not found"}}
                ),
                404,
            )
        return jsonify(user.to_dict()), 200
    except Exception as e:
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    try:
        user_id = get_jwt_identity()
        access_token = create_access_token(identity=user_id)
        return (
            jsonify(
                {
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": current_app.config[
                        "JWT_ACCESS_TOKEN_EXPIRES"
                    ].total_seconds(),
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    try:
        user_id = get_jwt_identity()
        now = datetime.now(timezone.utc)

        # Delete all active sessions for this user, not just already-expired ones
        Session.query.filter(
            Session.user_id == user_id, Session.expires_at > now
        ).delete()

        # Also clean up any lingering expired sessions
        Session.query.filter(
            Session.user_id == user_id, Session.expires_at <= now
        ).delete()

        db.session.commit()
        return jsonify({"message": "Logged out"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500


@auth_bp.route("/verify-email/<string:token>", methods=["GET"])
def verify_email(token):
    try:
        verification = EmailVerification.query.filter_by(
            verification_token=token
        ).first()
        if not verification:
            return (
                jsonify(
                    {"error": {"code": "INVALID_TOKEN", "message": "Invalid token"}}
                ),
                400,
            )

        if verification.verified_at:
            return (
                jsonify(
                    {
                        "error": {
                            "code": "ALREADY_VERIFIED",
                            "message": "Already verified",
                        }
                    }
                ),
                400,
            )

        if is_token_expired(verification.expires_at):
            return (
                jsonify(
                    {"error": {"code": "TOKEN_EXPIRED", "message": "Token expired"}}
                ),
                400,
            )

        user = User.query.get(verification.user_id)
        if not user:
            return (
                jsonify(
                    {"error": {"code": "USER_NOT_FOUND", "message": "User not found"}}
                ),
                404,
            )

        verification.verified_at = datetime.now(timezone.utc)
        user.is_verified = True
        db.session.commit()

        return jsonify({"message": "Email verified"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500


@auth_bp.route("/resend-verification", methods=["POST"])
@jwt_required()
def resend_verification():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user:
            return (
                jsonify(
                    {"error": {"code": "USER_NOT_FOUND", "message": "User not found"}}
                ),
                404,
            )

        if user.is_verified:
            return (
                jsonify(
                    {
                        "error": {
                            "code": "ALREADY_VERIFIED",
                            "message": "Already verified",
                        }
                    }
                ),
                400,
            )

        token = generate_token(32)
        verification = EmailVerification(
            user_id=user.id,
            verification_token=token,
            expires_at=get_token_expiry(
                current_app.config["VERIFICATION_TOKEN_EXPIRY"]
            ),
        )
        db.session.add(verification)
        db.session.commit()

        send_verification_email(user, token)
        return jsonify({"message": "Verification email sent"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500
