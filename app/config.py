import os
import secrets
from datetime import timedelta

class Config:
    # JWT
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_hex(32))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=int(os.environ.get("JWT_ACCESS_MINUTES", 15)))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os.environ.get("JWT_REFRESH_DAYS", 7)))
    JWT_TOKEN_LOCATION = ["headers"]

    # MongoDB
    MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME","bits_of_me")

    # OTP
    OTP_SECRET_KEY = os.environ.get("OTP_SECRET_KEY", secrets.token_hex(32))
    OTP_TTL_SEC = int(os.environ.get("OTP_TTL_SEC", 300))
    OTP_DIGITS = int(os.environ.get("OTP_DIGITS", 6))

    # CORS
    CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "http://localhost:4200")
