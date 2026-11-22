# The Django quickstart as a demo application of deploy/docker-compose.yml's `demo`
# profile, at http://localhost:8093/login/. Django, Authlib and requests at the
# versions requirements.in pins, and everything under them as requirements.txt records
# it, each with its hashes, which pip refuses to install without; the base pinned by
# digest, as every image here is (TestEveryBaseImageIsPinnedByDigest).
FROM python:3.14.10-slim-trixie@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --root-user-action=ignore --require-hashes -r requirements.txt
COPY manage.py ./
COPY quickstart ./quickstart
# By number, so runAsNonRoot can check it; nothing here writes to disk.
USER 65532:65532
# A DJANGO_SECRET_KEY made at each start unless one is given, so none is baked into the
# image. It signs the session cookie, so a restart ends the sign-ins in flight.
# runserver is Django's development server, which is what a demo needs.
CMD ["sh", "-c", "export DJANGO_SECRET_KEY=\"${DJANGO_SECRET_KEY:-$(python -c 'import secrets; print(secrets.token_urlsafe(50))')}\" && exec python manage.py runserver --noreload \"127.0.0.1:${PORT:-8000}\""]
