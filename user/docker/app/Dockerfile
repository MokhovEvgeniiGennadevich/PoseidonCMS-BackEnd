FROM php:8.1-fpm

RUN apt-get update && \
    docker-php-ext-install pdo_mysql && \
    docker-php-ext-install mysqli && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY ./docker/app/php.ini /usr/local/etc/php/conf.d/php.ini

WORKDIR /var/www

