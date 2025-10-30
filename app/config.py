import os
import secrets
from datetime import timedelta

class Config:
    # JWT
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_hex(32))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=int(os.environ.get("JWT_ACCESS_MINUTES", 15)))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os.environ.get("JWT_REFRESH_DAYS", 7)))
    JWT_TOKEN_LOCATION = [os.environ.get("JWT_TOKEN_LOCATION", "headers")]
    JWT_COOKIE_SECURE = True
    JWT_COOKIE_SAMESITE = "Lax"
    JWT_COOKIE_CSRF_PROTECT = True
    
    # Redis
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    
    # Mail
    MAIL_SERVER = os.environ.get("MAIL_SERVER")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USE_SSL = os.environ.get("MAIL_USE_SSL", "false").lower() == "true"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_SENDER", "no-reply@example.com")
    
    # OTP
    OTP_SECRET_KEY = os.environ.get("OTP_SECRET_KEY", secrets.token_hex(32))
    OTP_TTL_SEC = int(os.environ.get("OTP_TTL_SEC", 600))
    OTP_DIGITS = int(os.environ.get("OTP_DIGITS", 6))
    OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", 5))
    
    # CORS
    CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "http://localhost:4200")
    
    # Dev
    SEND_CONSOLE = os.environ.get('SEND_CONSOLE', '1') == '1'
