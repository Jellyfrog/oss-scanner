# LibreNMS image for the OSS Scanner of Anthropic (https://github.com/anthropics/oss-scanner).
#
# The scanner builds this image with the LibreNMS checkout as the build context. Then the scanner runs the image as
# root in /src, with no network and no init system. When a container starts, no service runs. `librenms-scanctl start`
# starts MariaDB, snmpsim and the web UI. Refer to threat_model.md and `librenms-scanctl help`.
#
# To build and run the image on your computer, use these commands in a LibreNMS checkout:
#   docker build -f /path/to/oss-scanner/projects/librenms/Dockerfile -t librenms-scan .
#   docker run --rm -it --network none librenms-scan bash
#   # librenms-scanctl start && curl -sI http://127.0.0.1:8000/login

FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive \
    COMPOSER_ALLOW_SUPERUSER=1

# This list is the package list for Debian 13 in doc/Installation/Install-LibreNMS.md, with these primary changes:
# - nginx, php-fpm and snmpd are not in the list, because `php artisan serve` serves the web UI.
# - composer, sqlite and the Python venv module are in the list, because the build and the test suite use them.
# - php-ldap is in the list for the LDAP and Active Directory auth backends.
RUN apt-get update && apt-get install -y --no-install-recommends \
      acl ca-certificates composer curl file fping git jq less mariadb-client mariadb-server mtr-tiny nmap procps \
      php-bcmath php-cli php-curl php-gd php-gmp php-intl php-ldap php-mbstring php-mysql php-snmp php-sqlite3 \
      php-xml php-zip \
      python3 python3-command-runner python3-dotenv python3-pip python3-psutil python3-pymysql python3-redis \
      python3-setuptools python3-venv \
      rrdtool snmp sqlite3 unzip whois \
    && rm -rf /var/lib/apt/lists/*

# LibreNMS runs as its own user, the same as a production installation. snmpsim also does not run as root.
RUN useradd --system --create-home --home-dir /var/lib/librenms --shell /bin/bash librenms \
    && git config --system --add safe.directory /src

# Scanner contract: the checkout is in the image, at /src.
COPY --chown=librenms:librenms . /src
WORKDIR /src

# These steps are the same as the CI steps (.github/actions/composer-install). The development dependencies stay,
# because the tests use them.
USER librenms
RUN composer install --prefer-dist --no-interaction --no-progress --no-scripts --no-autoloader \
    && composer dump --strict-psr --strict-ambiguous --no-interaction --no-scripts

# This step installs snmpsim at the version and path that LibreNMS/Util/Snmpsim.php uses. As a result, the tests do
# not download snmpsim later, when there is no network.
ARG SNMPSIM_VERSION=2.0.1
RUN python3 -m venv .python_venvs/snmpsim \
    && .python_venvs/snmpsim/bin/pip install --no-cache-dir -q \
      "https://github.com/librenms/snmpsim/releases/download/v${SNMPSIM_VERSION}/snmpsim-${SNMPSIM_VERSION}-py3-none-any.whl"

# This configuration is for the image only. The live instance uses the database `librenms`. The test suite uses a
# different database, the same as CI (.github/workflows/test.yml).
# APP_ENV is not in this file. Without APP_ENV, the live instance runs as `production`, and phpunit can set `testing`.
COPY --chown=librenms:librenms <<'EOF' /src/.env
APP_KEY=
APP_URL=http://127.0.0.1:8000
APP_DEBUG=false
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=librenms
DB_USERNAME=librenms
DB_PASSWORD=librenms
DB_TEST_DRIVER=mysql
DB_TEST_HOST=127.0.0.1
DB_TEST_PORT=3306
DB_TEST_DATABASE=librenms_phpunit_78hunjuybybh
DB_TEST_USERNAME=librenms
DB_TEST_PASSWORD=librenms
EOF
RUN php artisan key:generate --force --no-interaction \
    && cp tests/testing_config.yaml database/seeders/config/ \
    && sqlite3 database/testing.sqlite ""
USER root

COPY --chmod=755 <<'EOF' /usr/local/bin/librenms-scanctl
#!/bin/bash
# librenms-scanctl -- run LibreNMS in the OSS Scanner image

SRC=/src
HOST="${LIBRENMS_HOST:-127.0.0.1}"
PORT="${LIBRENMS_PORT:-8000}"
SITE="http://127.0.0.1:$PORT"
PASSWORD=LibreNMS-scan-1234
SNMPSIM_PORT=1161
# NAME:ADDRESS. NAME is the SNMP community, and it selects the recording tests/snmpsim/NAME.snmprec.
DEVICES="linux:127.1.6.11 ios:127.1.6.12 routeros:127.1.6.13"
TESTDB=librenms_phpunit_78hunjuybybh
ETCDIR=/etc/librenms-scan
LOGDIR=/var/log/librenms-scan
RUNDIR=/run/librenms-scan

usage () {
    cat <<__EOF__
Usage: librenms-scanctl COMMAND [ARGS]

The image has no init system and no network. Start the services that you need.

Commands:
  start        Start MariaDB, snmpsim and the web UI at $SITE/.
               With LIBRENMS_HOST=0.0.0.0, the web UI listens on all interfaces.
  stop         Stop the web UI, snmpsim and MariaDB.
  status       Show the services that run.
  reset        Build the live database and its sample data again.
  poll         Discover and poll the sample devices with snmpsim.
  test [ARGS]  Start MariaDB. Then run \`lnms dev:check unit --db --snmpsim ARGS\`.
               The default ARGS select the CI tests without the per-OS tests.
  phpunit [ARGS]
               Start MariaDB. Then run \`vendor/bin/phpunit ARGS\` with DBTEST=1.
  db [NAME]    Start MariaDB. Then open an SQL shell on librenms (or NAME).
  as CMD...    Run CMD in $SRC as the librenms user.
               Example: \`librenms-scanctl as ./lnms device:poll 127.1.6.11\`
  setup        Create the databases and the sample data. Use this command only in the image build.

The password of each account is \`$PASSWORD\`.
  admin        role admin
  reader       role global-read
  user         role user, with access to the device \`linux\` only
  user2        role user, with access to no device
The API tokens (header \`X-Auth-Token\`) are in $ETCDIR/USERNAME.token.

Devices (the host name is the address, the display name is NAME):
  linux        127.1.6.11
  ios          127.1.6.12
  routeros     127.1.6.13
snmpsim answers for them on UDP port $SNMPSIM_PORT. snmpsim uses $SRC/tests/snmpsim/NAME.snmprec.
The SNMP community is NAME. \`lnms dev:simulate\` uses 127.1.6.1:1161, which stays free.

Files:
  $SRC/.env                 database and application configuration
  $SRC/logs/librenms.log    application log
  $LOGDIR    mariadb.log, snmpsim.log, web.log
__EOF__
}

as_librenms () {
    (cd "$SRC" && runuser -u librenms -- "$@")
}

db_running () {
    mariadb-admin ping >/dev/null 2>&1
}

db_start () {
    db_running && return 0
    mkdir -p /run/mysqld "$LOGDIR"
    chown mysql:mysql /run/mysqld
    /usr/sbin/mariadbd --user=mysql >>"$LOGDIR/mariadb.log" 2>&1 </dev/null &
    for i in $(seq 1 120); do
        db_running && return 0
        sleep 0.5
    done
    echo "librenms-scanctl: MariaDB did not start. Refer to $LOGDIR/mariadb.log." 1>&2
    exit 1
}

db_stop () {
    db_running && mariadb-admin shutdown
}

pid_running () {
    test -f "$1" && kill -0 "$(cat "$1")" 2>/dev/null
}

rundirs () {
    mkdir -p "$RUNDIR" "$LOGDIR"
    chown librenms:librenms "$RUNDIR" "$LOGDIR"
}

snmpsim_start () {
    pid_running "$RUNDIR/snmpsim.pid" && return 0
    rundirs
    endpoints=()
    for device in $DEVICES; do
        endpoints+=(--agent-udpv4-endpoint="${device#*:}:$SNMPSIM_PORT")
    done
    # When snmpsim answers, the --daemonize command returns.
    as_librenms .python_venvs/snmpsim/bin/snmpsim-command-responder-lite --daemonize \
        --pid-file="$RUNDIR/snmpsim.pid" --data-dir=tests/snmpsim "${endpoints[@]}" \
        --log-level=error --logging-method="file:$LOGDIR/snmpsim.log"
}

web_start () {
    pid_running "$RUNDIR/web.pid" && return 0
    rundirs
    # setsid gives the web UI its own process group. Then `stop` can stop the group and no other process.
    (cd "$SRC" || exit 1
     PHP_CLI_SERVER_WORKERS=4 setsid runuser -u librenms -- \
        php artisan serve --host="$HOST" --port="$PORT" >>"$LOGDIR/web.log" 2>&1 </dev/null &
     echo $! > "$RUNDIR/web.pid")
    for i in $(seq 1 60); do
        curl -s -o /dev/null "$SITE/login" && return 0
        sleep 0.5
    done
    echo "librenms-scanctl: The web UI did not start. Refer to $LOGDIR/web.log." 1>&2
    exit 1
}

stop_pid () {
    pid_running "$1" && kill "$(cat "$1")"
    rm -f "$1"
}

web_stop () {
    # The pid is the leader of the process group of the web UI. Send the signal to the full group.
    pid_running "$RUNDIR/web.pid" && kill -- "-$(cat "$RUNDIR/web.pid")"
    rm -f "$RUNDIR/web.pid"
}

# Create the live database, the sample users, the sample devices and the API tokens.
seed () (
    set -e
    mariadb -e "DROP DATABASE IF EXISTS librenms"
    mariadb -e "CREATE DATABASE librenms CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
    as_librenms php artisan migrate --force --seed --no-interaction

    for account in admin:admin reader:global-read user:user user2:user; do
        as_librenms ./lnms user:add "${account%%:*}" --password="$PASSWORD" --role="${account#*:}" \
            --email="${account%%:*}@example.org" --full-name="Sample ${account#*:}" --no-interaction
    done

    # Most recordings have the same sysName (`<private>`).
    as_librenms ./lnms config:set allow_duplicate_sysName true --no-interaction
    snmpsim_start
    for device in $DEVICES; do
        as_librenms ./lnms device:add "${device#*:}" --v2c --community="${device%%:*}" --port="$SNMPSIM_PORT" \
            --display-name="${device%%:*}" --no-interaction
    done

    # `user` is a normal user who can see only the device `linux`. No lnms command gives this access.
    mariadb librenms -e "INSERT INTO devices_perms (user_id, device_id)
        SELECT user_id, device_id FROM users, devices WHERE username = 'user' AND community = 'linux'"

    mkdir -p "$ETCDIR"
    for account in admin reader user user2; do
        as_librenms ./lnms api:token-create "$account" --name=oss-scanner --no-ansi \
            | grep -oE '[0-9]+\|[A-Za-z0-9]{40,}' > "$ETCDIR/$account.token"
    done
)

cmd_poll () {
    db_start
    snmpsim_start
    for device in $DEVICES; do
        as_librenms ./lnms device:discover "${device#*:}" --no-interaction
        as_librenms ./lnms device:poll "${device#*:}" --no-interaction
    done
}

cmd_setup () {
    set -e
    db_start
    mariadb <<__EOF__
CREATE DATABASE IF NOT EXISTS $TESTDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'librenms'@'%' IDENTIFIED BY 'librenms';
CREATE USER IF NOT EXISTS 'librenms'@'localhost' IDENTIFIED BY 'librenms';
GRANT ALL PRIVILEGES ON librenms.* TO 'librenms'@'%', 'librenms'@'localhost';
GRANT ALL PRIVILEGES ON $TESTDB.* TO 'librenms'@'%', 'librenms'@'localhost';
__EOF__
    seed
    # The test suite uses a migrated database, the same as CI.
    (cd "$SRC" && DB_DATABASE="$TESTDB" runuser -u librenms -- php artisan migrate --force --no-interaction)
    stop_pid "$RUNDIR/snmpsim.pid"
    db_stop
}

cmd_status () {
    if db_running; then echo "MariaDB: running"; else echo "MariaDB: stopped"; fi
    if pid_running "$RUNDIR/snmpsim.pid"; then echo "snmpsim: $DEVICES"; else echo "snmpsim: stopped"; fi
    if pid_running "$RUNDIR/web.pid"; then echo "web UI: $SITE/"; else echo "web UI: stopped"; fi
}

cmd=${1:-help}
shift
case "$cmd" in
setup)  cmd_setup;;
start)  db_start; snmpsim_start; web_start
        echo "LibreNMS serves $SITE/"
        echo "The password of each account is $PASSWORD. \`librenms-scanctl help\` shows the accounts.";;
stop)   web_stop; stop_pid "$RUNDIR/snmpsim.pid"; db_stop;;
status) cmd_status;;
reset)  db_start; seed;;
poll)   cmd_poll;;
test)   db_start
        if [ $# -eq 0 ]; then set -- --full --exclude-phpunit-group=browser,mibs,external-dependencies,os; fi
        as_librenms ./lnms dev:check unit --db --snmpsim "$@";;
phpunit) db_start; as_librenms env DBTEST=1 vendor/bin/phpunit "$@";;
db)     db_start; exec mariadb "${1:-librenms}";;
as)     as_librenms "$@";;
help|-h|--help) usage;;
*)      usage 1>&2; exit 1;;
esac
EOF

# Create the databases and the sample data. Then stop MariaDB correctly, so that its data directory is in the image.
RUN librenms-scanctl setup

# Discover and poll the sample devices one time. Then the instance has ports, sensors and RRD files. An error here
# does not stop the build.
RUN librenms-scanctl poll > /var/log/librenms-scan-poll.log 2>&1 \
    || echo "WARNING: The poll of the sample devices was not successful. Refer to /var/log/librenms-scan-poll.log."; \
    librenms-scanctl stop || true

# Smoke tests. The build log shows if the image works. First, start the instance one time. Then run the CI unit tests
# without the per-OS tests. To run the per-OS tests, use `librenms-scanctl test --os NAME`. An error here does not stop
# the build.
RUN (librenms-scanctl start && curl -fsS -o /dev/null -w 'login page: HTTP %{http_code}\n' http://127.0.0.1:8000/login) \
    || echo "WARNING: The smoke test of the web UI was not successful."; \
    librenms-scanctl stop || true
RUN timeout 15m librenms-scanctl test \
    || echo "WARNING: The unit tests found errors, or the time limit stopped them."; \
    librenms-scanctl stop || true
