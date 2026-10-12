# LibreNMS image for the OSS Scanner of Anthropic (https://github.com/anthropics/oss-scanner).
#
# The scanner builds this image with the LibreNMS checkout as the build context. Then the scanner runs the image as
# root in /src, with no network and no init system. threat_model.md gives the commands that start the services.

FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive

# This list is the package list for Debian 13 in doc/Installation/Install-LibreNMS.md, without nginx, php-fpm and
# snmpd. The build and the test suite also use composer, php-sqlite3, sqlite3 and python3-venv. php-ldap is for the
# LDAP and Active Directory auth backends.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates composer curl fping git mariadb-client mariadb-server mtr-tiny nmap \
      php-cli php-curl php-gd php-gmp php-ldap php-mbstring php-mysql php-snmp php-sqlite3 php-xml php-zip \
      python3-command-runner python3-dotenv python3-psutil python3-pymysql python3-redis python3-setuptools \
      python3-venv rrdtool snmp sqlite3 whois \
    && rm -rf /var/lib/apt/lists/*

# lnms does not run as root. LibreNMS runs as the user `librenms`, the same as a production installation.
RUN useradd --system --create-home --home-dir /var/lib/librenms --shell /bin/bash librenms \
    && git config --system --add safe.directory /src

# Scanner contract: the checkout is in the image, at /src.
COPY --chown=librenms:librenms . /src
WORKDIR /src
USER librenms

# These steps are the same as the CI steps (.github/actions/composer-install). The development dependencies stay,
# because the tests use them.
RUN composer install --prefer-dist --no-interaction --no-progress --no-scripts --no-autoloader \
    && composer dump --strict-psr --strict-ambiguous --no-interaction --no-scripts \
    && composer clear-cache

# APP_ENV is not in this file. Without APP_ENV, the live instance runs as `production`, and phpunit can set `testing`.
COPY --chown=librenms:librenms <<'EOF' .env
APP_KEY=
APP_URL=http://127.0.0.1:8000
DB_HOST=127.0.0.1
DB_PASSWORD=librenms
DB_TEST_HOST=127.0.0.1
DB_TEST_USERNAME=librenms
DB_TEST_PASSWORD=librenms
PHP_CLI_SERVER_WORKERS=4
EOF

# Install snmpsim now, because there is no network later.
RUN php artisan key:generate --force \
    && ./lnms dev:simulate --setup-venv \
    && test -x .python_venvs/snmpsim/bin/snmpsim-command-responder-lite

# Create the live database, the test database and the sample users. The password of each user is `LibreNMS-scan-1234`.
USER root
RUN service mariadb start \
    && mariadb -e "CREATE DATABASE librenms CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; \
        CREATE DATABASE librenms_phpunit_78hunjuybybh CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; \
        CREATE USER 'librenms'@'%' IDENTIFIED BY 'librenms'; \
        GRANT ALL PRIVILEGES ON librenms.* TO 'librenms'@'%'; \
        GRANT ALL PRIVILEGES ON librenms_phpunit_78hunjuybybh.* TO 'librenms'@'%'" \
    && runuser -u librenms -- php artisan migrate --force --seed \
    && runuser -u librenms -- php artisan migrate --force --database=testing \
    && runuser -u librenms -- ./lnms user:add admin --password=LibreNMS-scan-1234 --role=admin \
    && runuser -u librenms -- ./lnms user:add reader --password=LibreNMS-scan-1234 --role=global-read \
    && runuser -u librenms -- ./lnms user:add user --password=LibreNMS-scan-1234 --role=user \
    && service mariadb stop

# Smoke test: the CI unit tests without the per-OS tests, with the same preparation as CI
# (.github/workflows/test.yml). An error here does not stop the build.
RUN service mariadb start \
    && (runuser -u librenms -- sh -c 'cp tests/testing_config.yaml database/seeders/config/ \
            && sqlite3 database/testing.sqlite "" \
            && timeout 15m ./lnms dev:check unit --db --snmpsim --full \
                --exclude-phpunit-group=browser,mibs,external-dependencies,os' \
        || echo "WARNING: The unit tests found errors, or the time limit stopped them."); \
    service mariadb stop
