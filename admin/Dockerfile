# The console: Laravel under php-fpm, as an unprivileged user, and nginx in front of
# it, unprivileged too. Two images from one file, run side by side:
#
#   docker build -t signari-console admin/
#   docker build -t signari-console-web --target web admin/
#
# Its database role is signari_admin and never anything wider (ADR-004): it reads
# the engine through core_v1 and writes through the engine's Admin API.

FROM composer:2.8 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
# The runtime below has intl and pdo_pgsql; this stage only lays out vendor/.
RUN composer install --no-dev --no-scripts --no-autoloader --prefer-dist --no-interaction --ignore-platform-reqs
COPY . .
RUN composer dump-autoload --optimize --classmap-authoritative --no-dev --no-scripts

FROM php:8.4-fpm-alpine AS app
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

FROM nginxinc/nginx-unprivileged:1.27-alpine AS web
COPY docker/default.conf.template /etc/nginx/templates/default.conf.template
ENV CONSOLE_FPM=console:9000
# The files a browser fetches, served by nginx; everything else goes to php-fpm.
COPY --from=app /app/public /app/public
EXPOSE 8080
