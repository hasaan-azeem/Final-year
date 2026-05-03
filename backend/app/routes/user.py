from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timezone
from app import db
from app.models import User, Session, PasswordReset
from app.utils import (
    hash_password,
    verify_password,
    generate_token,
    get_token_expiry,
    is_token_expired,
    send_password_reset_email,
    validate_password_strength,
)

user_bp = Blueprint("user", __name__)


@user_bp.route("/me", methods=["GET"])
@jwt_required()
def get_current_user():
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


@user_bp.route("/me", methods=["PUT"])
@jwt_required()
def update_current_user():
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

        max_username = current_app.config.get("MAX_USERNAME_LENGTH", 50)
        max_full_name = current_app.config.get("MAX_FULL_NAME_LENGTH", 120)
        max_avatar_url = current_app.config.get("MAX_AVATAR_URL_LENGTH", 500)

        if "username" in data:
            username = data["username"].strip()
            if len(username) > max_username:
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
            if username and username != user.username:
                if User.query.filter_by(username=username).first():
                    return (
                        jsonify(
                            {
                                "error": {
                                    "code": "USERNAME_TAKEN",
                                    "message": "Username taken",
                                }
                            }
                        ),
                        409,
                    )
                user.username = username

        if "full_name" in data:
            full_name = data["full_name"].strip()
            if len(full_name) > max_full_name:
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
            user.full_name = full_name

        if "avatar_url" in data:
            avatar_url = data["avatar_url"].strip()
            if len(avatar_url) > max_avatar_url:
                return (
                    jsonify(
                        {
                            "error": {
                                "code": "VALIDATION_ERROR",
                                "message": f"Avatar URL too long (max {max_avatar_url} chars)",
                            }
                        }
                    ),
                    400,
                )
            user.avatar_url = avatar_url

        user.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        return jsonify(user.to_dict()), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500


@user_bp.route("/me/password", methods=["PUT"])
@jwt_required()
def change_password():
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

        current_password = data.get("current_password")
        new_password = data.get("new_password")

        if not current_password or not new_password:
            return (
                jsonify(
                    {
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Passwords required",
                        }
                    }
                ),
                400,
            )

        # Validate new password strength
        password_error = validate_password_strength(new_password)
        if password_error:
            return (
                jsonify(
                    {"error": {"code": "WEAK_PASSWORD", "message": password_error}}
                ),
                400,
            )

        if user.password_hash and not verify_password(
            user.password_hash, current_password
        ):
            return (
                jsonify(
                    {
                        "error": {
                            "code": "INVALID_PASSWORD",
                            "message": "Incorrect password",
                        }
                    }
                ),
                401,
            )

        user.password_hash = hash_password(new_password)
        user.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        return jsonify({"message": "Password updated"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500


@user_bp.route("/me/sessions", methods=["GET"])
@jwt_required()
def get_user_sessions():
    try:
        user_id = get_jwt_identity()
        now = datetime.now(timezone.utc)
        sessions = (
            Session.query.filter(Session.user_id == user_id, Session.expires_at > now)
            .order_by(Session.created_at.desc())
            .all()
        )
        return jsonify({"sessions": [s.to_dict() for s in sessions]}), 200
    except Exception as e:
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500


@user_bp.route("/me/sessions/<int:session_id>", methods=["DELETE"])
@jwt_required()
def delete_session(session_id):
    try:
        user_id = get_jwt_identity()
        session = Session.query.filter_by(id=session_id, user_id=user_id).first()
        if not session:
            return (
                jsonify(
                    {
                        "error": {
                            "code": "SESSION_NOT_FOUND",
                            "message": "Session not found",
                        }
                    }
                ),
                404,
            )
        db.session.delete(session)
        db.session.commit()
        return jsonify({"message": "Session revoked"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500


@user_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
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
        if not email:
            return (
                jsonify(
                    {"error": {"code": "VALIDATION_ERROR", "message": "Email required"}}
                ),
                400,
            )

        # Always return the same response to prevent user enumeration
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"message": "If account exists, reset email sent"}), 200

        token = generate_token(32)
        reset = PasswordReset(
            user_id=user.id,
            reset_token=token,
            expires_at=get_token_expiry(current_app.config["RESET_TOKEN_EXPIRY"]),
        )
        db.session.add(reset)
        db.session.commit()

        send_password_reset_email(user, token)
        return jsonify({"message": "If account exists, reset email sent"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500


@user_bp.route("/reset-password", methods=["POST"])
def reset_password():
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

        token = data.get("token")
        new_password = data.get("password")

        if not token or not new_password:
            return (
                jsonify(
                    {
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Token and password required",
                        }
                    }
                ),
                400,
            )

        # Validate new password strength
        password_error = validate_password_strength(new_password)
        if password_error:
            return (
                jsonify(
                    {"error": {"code": "WEAK_PASSWORD", "message": password_error}}
                ),
                400,
            )

        reset = PasswordReset.query.filter_by(reset_token=token).first()
        if not reset:
            return (
                jsonify(
                    {"error": {"code": "INVALID_TOKEN", "message": "Invalid token"}}
                ),
                400,
            )

        if reset.used_at:
            return (
                jsonify(
                    {"error": {"code": "TOKEN_USED", "message": "Token already used"}}
                ),
                400,
            )

        if is_token_expired(reset.expires_at):
            return (
                jsonify(
                    {"error": {"code": "TOKEN_EXPIRED", "message": "Token expired"}}
                ),
                400,
            )

        user = User.query.get(reset.user_id)
        if not user:
            return (
                jsonify(
                    {"error": {"code": "USER_NOT_FOUND", "message": "User not found"}}
                ),
                404,
            )

        user.password_hash = hash_password(new_password)
        user.updated_at = datetime.now(timezone.utc)
        reset.used_at = datetime.now(timezone.utc)
        db.session.commit()

        return jsonify({"message": "Password reset successful"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": {"code": "SERVER_ERROR", "message": str(e)}}), 500
