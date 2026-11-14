"""The least a Django application needs to sign people in with Signari.

A sign-in's state, nonce and PKCE verifier live in the session between the redirect out
and the callback. The session is a signed cookie, so the quickstart needs no database;
the cookie is signed, not encrypted, which is fine for what only its own browser holds.
"""
import os

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DEBUG = False
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

INSTALLED_APPS = []
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
]
ROOT_URLCONF = "quickstart.urls"
DATABASES = {}
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = os.environ.get("REDIRECT_URI", "").startswith("https:")
USE_TZ = True
