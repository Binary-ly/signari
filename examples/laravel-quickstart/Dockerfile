# The Laravel quickstart as a demo application of deploy/docker-compose.yml's `demo`
# profile, at http://localhost:8095/login: what docs/quickstart-laravel.md has you do by
# hand, a fresh laravel/laravel 13.11.0 with jumbojett/openid-connect-php 1.0.2 and
# this directory's files laid over it. Both bases pinned by digest, as every image here
# is (TestEveryBaseImageIsPinnedByDigest); the runtime's PHP is the composer image's.
FROM composer:2.11.2@sha256:5bcb28b8d0edc4091125f8218f9d088f998bdfc843f8fbb9a4beb4dcd8625684 AS vendor
WORKDIR /app
# No scripts: a fresh project's would write an .env with an APP_KEY in it, which an image
# must not carry, and make a database this application never uses.
RUN composer create-project --no-dev --no-scripts --prefer-dist --no-interaction laravel/laravel:13.11.0 . \
 && composer require --update-no-dev --no-scripts --prefer-dist --no-interaction jumbojett/openid-connect-php:1.0.2
COPY app ./app
COPY config ./config
COPY routes ./routes

FROM php:8.5.12-cli-alpine3.24@sha256:1ff5b45922ab30f418447c6089dbe2eba5f01e0b2742863d0327ac349305d70f
WORKDIR /app
COPY --from=vendor /app /app
RUN php artisan package:discover --ansi && chown -R 82:82 storage bootstrap/cache
# Sessions and cache in files, so there is no database; logs to the container's output.
ENV APP_ENV=production APP_DEBUG=false LOG_CHANNEL=stderr SESSION_DRIVER=file CACHE_STORE=file
# www-data by number, so runAsNonRoot can check it.
USER 82:82
# An APP_KEY made at each start unless one is given, so none is baked into the image.
# It encrypts the session cookie, so a restart ends the sign-ins in flight.
# The settings come from the container's environment; there is no .env. --no-reload keeps
# it so if one is added: with an .env and without the flag, `serve` passes the server only
# a short list of variables, and the SIGNARI_* settings would not reach the application.
CMD ["sh", "-c", "export APP_KEY=\"${APP_KEY:-base64:$(head -c 32 /dev/urandom | base64)}\" && exec php artisan serve --no-reload --host=127.0.0.1 --port=\"${PORT:-8000}\""]
