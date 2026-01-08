FROM php:8.1-apache

# Metadata
LABEL maintainer="Security Testing"
LABEL description="SLiMS 9 For Testing"

ENV SLIMS_VERSION=9.7.2 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        unzip \
        curl \
        libpng-dev \
        libjpeg-dev \
        libfreetype6-dev \
        libzip-dev \
        libonig-dev \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-configure gd --with-freetype --with-jpeg && \
    docker-php-ext-install -j$(nproc) \
        mysqli \
        pdo_mysql \
        gd \
        zip \
        mbstring \
        gettext

RUN cd /var/www/html && \
    curl -fSL "https://github.com/slims/slims9_bulian/archive/refs/tags/v${SLIMS_VERSION}.zip" -o slims.zip && \
    unzip -q slims.zip && \
    mv slims9_bulian-${SLIMS_VERSION} slims && \
    rm slims.zip

RUN chown -R www-data:www-data /var/www/html/slims && \
    chmod -R 755 /var/www/html/slims && \
    chmod -R 777 /var/www/html/slims/config \
                 /var/www/html/slims/images \
                 /var/www/html/slims/files \
                 /var/www/html/slims/repository

RUN a2enmod rewrite && \
    sed -i 's#/var/www/html#/var/www/html/slims#g' /etc/apache2/sites-available/000-default.conf

RUN echo "display_errors = On" > /usr/local/etc/php/conf.d/testing.ini && \
    echo "error_reporting = E_ALL" >> /usr/local/etc/php/conf.d/testing.ini && \
    echo "upload_max_filesize = 20M" >> /usr/local/etc/php/conf.d/testing.ini && \
    echo "post_max_size = 20M" >> /usr/local/etc/php/conf.d/testing.ini && \
    echo "log_errors = On" >> /usr/local/etc/php/conf.d/testing.ini

WORKDIR /var/www/html/slims

EXPOSE 80

CMD ["apache2-foreground"]