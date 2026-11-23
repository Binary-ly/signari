# The console: Laravel under php-fpm, as an unprivileged user, and nginx in front of
# it, unprivileged too. Two images from one file, run side by side:
#
#   docker build -t signari-console admin/
#   docker build -t signari-console-web --target web admin/
#
# Its database role is signari_admin and never anything wider (ADR-004): it reads
# the engine through core_v1 and writes through the engine's Admin API.
#
# Each base pinned to a digest, as engine/Dockerfile's are and for its reason. The
# packages apk adds below are not pinned, so this image is not one that rebuilds
# byte for byte; the base it starts from is.

FROM composer:2.11@sha256:50ea4d33fdcde1adb0f045547295faa1548b33872e5f789dae5b02ce2fb5de93 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
# The runtime below has intl and pdo_pgsql; this stage only lays out vendor/.
RUN composer install --no-dev --no-scripts --no-autoloader --prefer-dist --no-interaction --ignore-platform-reqs
COPY . .
RUN composer dump-autoload --optimize --classmap-authoritative --no-dev --no-scripts

FROM php:8.5-fpm-alpine@sha256:51414d5291758fe27f58a64c7e8a078465d32cc7dcef7bda803f5b36019802e0 AS app
RUN apk add --no-cache icu-libs libpq \
 && apk add --no-cache --virtual .build icu-dev postgresql-dev \
 && docker-php-ext-install intl pdo_pgsql opcache \
 && apk del .build
WORKDIR /app
COPY --from=vendor /app /app
# Ignored by git and by the build, so made here, and the only places it writes.
RUN mkdir -p storage/framework/cache/data storage/framework/sessions storage/framework/views \
      storage/logs bootstrap/cache \
 && php artisan package:discover --ansi \
 && chown -R www-data:www-data storage bootstrap/cache
# Logs to the container's output, not to a file nobody reads.
ENV LOG_CHANNEL=stderr
# www-data by number, which is what Kubernetes' runAsNonRoot can check.
USER 82:82
EXPOSE 9000
CMD ["php-fpm", "--nodaemonize"]

FROM nginxinc/nginx-unprivileged:1.31-alpine@sha256:b5047b9b76845eac124358373c6852377c52e4b05834a47647e955dd91cb8f1e AS web
COPY docker/default.conf.template /etc/nginx/templates/default.conf.template
ENV CONSOLE_FPM=console:9000
# The files a browser fetches, served by nginx; everything else goes to php-fpm.
COPY --from=app /app/public /app/public
EXPOSE 8080
