"""Signing people in with Signari through Authlib: the authorization code flow with PKCE,
the state taken back once, and the ID token's signature checked against the published
keys with its issuer, audience, expiry and nonce. See docs/quickstart-django.md."""
import os

from authlib.integrations.django_client import OAuth, OAuthError
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseServerError
from django.utils.html import escape

ISSUER = os.environ["SIGNARI_ISSUER"]
REDIRECT_URI = os.environ["REDIRECT_URI"]
SECRET = os.environ.get("CLIENT_SECRET")

oauth = OAuth()
oauth.register(
    name="signari",
    client_id=os.environ["CLIENT_ID"],
    client_secret=SECRET,
    server_metadata_url=ISSUER.rstrip("/") + "/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile",
        # Signari requires PKCE of every client, confidential ones included, and S256 only.
        "code_challenge_method": "S256",
        # A confidential client proves itself with its secret; a public one has only PKCE.
        "token_endpoint_auth_method": "client_secret_basic" if SECRET else "none",
    },
)


def home(request):
    return HttpResponse('<p><a href="/login/">Sign in with Signari</a></p>')


def login(request):
    # The document has to be the configured issuer's own: Authlib holds the ID token to
    # whatever issuer the document names, so a document naming another is refused here.
    if oauth.signari.load_server_metadata().get("issuer") != ISSUER:
        return HttpResponseServerError("the discovery document names another issuer")
    return oauth.signari.authorize_redirect(request, REDIRECT_URI)


def callback(request):
    try:
        token = oauth.signari.authorize_access_token(request)
    except OAuthError as err:
        # The server's own words, which docs/troubleshooting.md explains, or Authlib's own
        # for a state this browser never began.
        return HttpResponseBadRequest("the sign-in was refused: " + escape(err.description or err.error))
    claims = token.get("userinfo") or {}
    if not claims:
        return HttpResponseBadRequest("the sign-in carried no ID token")
    return HttpResponse("<p>Signed in as %s</p>" % escape(claims.get("email") or claims["sub"]))
