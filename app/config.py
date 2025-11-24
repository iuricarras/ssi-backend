import os
import secrets
from datetime import timedelta

class Config:
    # JWT
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_hex(32))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=int(os.environ.get("JWT_ACCESS_MINUTES", 15)))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os.environ.get("JWT_REFRESH_DAYS", 7)))

    # Aqui mudamos:
    JWT_TOKEN_LOCATION = ["cookies"]
    JWT_COOKIE_SECURE = False
    JWT_COOKIE_SAMESITE = "Lax"
    JWT_COOKIE_HTTPONLY = True
    JWT_ACCESS_COOKIE_PATH = "/api/"
    JWT_REFRESH_COOKIE_PATH = "/api/auth/refresh"
    JWT_COOKIE_CSRF_PROTECT = False

    # MongoDB
    MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "bits_of_me")

    # OTP
    OTP_SECRET_KEY = os.environ.get("OTP_SECRET_KEY", secrets.token_hex(32))
    OTP_TTL_SEC = int(os.environ.get("OTP_TTL_SEC", 300))
    OTP_DIGITS = int(os.environ.get("OTP_DIGITS", 6))

    # Assinatura Digital
    NONCE_TTL_SEC = int(os.environ.get("NONCE_TTL_SEC", 300))
    SIGNATURE_ALG = os.environ.get("SIGNATURE_ALG", "ECDSA_SHA256")
    SIGNATURE_KEY_TYPE = os.environ.get("SIGNATURE_KEY_TYPE", "EC_P256")

    # Email
    MAIL_SERVER = os.environ.get("MAIL_SERVER")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER")

    # CORS
    CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "http://localhost:4200")

    # SWAGGER
    SWAGGER = {
        "swagger_ui_config": {
            "withCredentials": True
        }
    }
