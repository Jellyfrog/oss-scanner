# LibreNMS image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
#
# The scanner builds this with the LibreNMS checkout as the build context, then runs the image as root in /src
# with no network and no init system. Nothing is running when a container starts: `librenms-scanctl start` brings up
# MariaDB, snmpsim and the web UI. See threat_model.md and `librenms-scanctl help`.
#
# Try it locally from a LibreNMS checkout:
#   docker build -f /path/to/oss-scanner/projects/librenms/Dockerfile -t librenms-scan .
#   docker run --rm -it --network none librenms-scan bash
#   # librenms-scanctl start && curl -sI http://127.0.0.1:8000/login

FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive \
    COMPOSER_ALLOW_SUPERUSER=1

# The package list of doc/Installation/Install-LibreNMS.md for Debian 13, without nginx/php-fpm/snmpd (the web UI is
# served by `php artisan serve`), plus what the test suite needs (sqlite, python venv) and php-ldap for the LDAP and
# Active Directory auth backends.
RUN apt-get update && apt-get install -y --no-install-recommends \
      acl ca-certificates composer curl file fping git jq less mariadb-client mariadb-server mtr-tiny nmap procps \
      php-bcmath php-cli php-curl php-gd php-gmp php-intl php-ldap php-mbstring php-mysql php-snmp php-sqlite3 \
      php-xml php-zip \
      python3 python3-command-runner python3-dotenv python3-pip python3-psutil python3-pymysql python3-redis \
      python3-setuptools python3-venv \
      rrdtool snmp sqlite3 unzip whois \
    && rm -rf /var/lib/apt/lists/*

# LibreNMS runs as its own user, as a real install does. snmpsim also refuses to run as root.
RUN useradd --system --create-home --home-dir /var/lib/librenms --shell /bin/bash librenms \
    && git config --system --add safe.directory /src

# scanner contract: the checkout lives inside the image, at /src
COPY --chown=librenms:librenms . /src
WORKDIR /src

# Same steps as CI (.github/actions/composer-install): development dependencies are kept, the tests need them.
USER librenms
RUN composer install --prefer-dist --no-interaction --no-progress --no-scripts --no-autoloader \
    && composer dump --strict-psr --strict-ambiguous --no-interaction --no-scripts

# snmpsim, at the version and path LibreNMS/Util/Snmpsim.php expects, so the tests do not try to download it later.
ARG SNMPSIM_VERSION=2.0.1
RUN python3 -m venv .python_venvs/snmpsim \
    && .python_venvs/snmpsim/bin/pip install --no-cache-dir -q \
      "https://github.com/librenms/snmpsim/releases/download/v${SNMPSIM_VERSION}/snmpsim-${SNMPSIM_VERSION}-py3-none-any.whl"

# Local-only settings. The live instance uses the database `librenms`; the test suite uses its own database, as in CI
# (.github/workflows/test.yml).
COPY --chown=librenms:librenms <<'EOF' /src/.env
APP_KEY=
APP_URL=http://127.0.0.1:8000
APP_ENV=production
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

# Creates the sample users, devices and API tokens. Run by `librenms-scanctl setup` and `reset`.
COPY --chmod=644 <<'EOF' /usr/local/lib/librenms-scan/seed.php
<?php

// usage: php seed.php PASSWORD TOKEN_DIR
require '/src/vendor/autoload.php';
$app = require '/src/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

use App\Models\Device;
use App\Models\User;
use Illuminate\Support\Facades\Artisan;

[, $password, $token_dir] = $argv;

// username => role. `user` is a normal user that may only see the device `linux`.
foreach (['admin' => 'admin', 'reader' => 'global-read', 'user' => 'user', 'user2' => 'user'] as $username => $role) {
    if (! User::where('username', $username)->exists()) {
        Artisan::call('user:add', [
            'username' => $username,
            '--password' => $password,
            '--role' => [$role],
            '--email' => "$username@example.org",
            '--full-name' => "Sample $role",
        ]);
        echo Artisan::output();
    }
}

// Same fields as `lnms dev:simulate --multiple FILE`: the community selects tests/snmpsim/FILE.snmprec.
foreach (['linux', 'ios', 'routeros'] as $community) {
    $device = Device::firstOrNew(['hostname' => $community]);
    $device->overwrite_ip = '127.1.6.1';
    $device->port = 1161;
    $device->snmpver = 'v2c';
    $device->transport = 'udp';
    $device->community = $community;
    $device->status_reason = '';
    $device->save();
}

$user = User::where('username', 'user')->firstOrFail();
$user->devicesOwned()->syncWithoutDetaching([Device::where('hostname', 'linux')->firstOrFail()->device_id]);

foreach (['admin', 'reader', 'user', 'user2'] as $username) {
    $account = User::where('username', $username)->firstOrFail();
    $account->tokens()->delete();
    file_put_contents("$token_dir/$username.token", $account->createToken('oss-scanner')->plainTextToken . "\n");
}
EOF

COPY --chmod=755 <<'EOF' /usr/local/bin/librenms-scanctl
#!/bin/bash
# librenms-scanctl -- run LibreNMS inside the OSS Scanner image

SRC=/src
HOST="${LIBRENMS_HOST:-127.0.0.1}"
PORT="${LIBRENMS_PORT:-8000}"
SITE="http://127.0.0.1:$PORT"
PASSWORD=LibreNMS-scan-1234
SNMPSIM_ENDPOINT=127.1.6.1:1161
TESTDB=librenms_phpunit_78hunjuybybh
ETCDIR=/etc/librenms-scan
LOGDIR=/var/log/librenms-scan
RUNDIR=/run/librenms-scan

usage () {
    cat <<__EOF__
Usage: librenms-scanctl COMMAND [ARGS]

The image has no init system and no network; start what you need yourself.

Commands:
  start        Start MariaDB, snmpsim and the web UI at $SITE/
               (LIBRENMS_HOST=0.0.0.0 listens on all interfaces)
  stop         Stop the web UI, snmpsim and MariaDB
  status       Report what is running
  reset        Rebuild the live database and its sample data
  poll         Discover and poll the sample devices against snmpsim
  test [ARGS]  Start MariaDB and run \`lnms dev:check unit --db --snmpsim ARGS\`
               (default ARGS: the CI selection without the per-OS tests)
  phpunit [ARGS]
               Start MariaDB and run \`vendor/bin/phpunit ARGS\` with DBTEST=1
  db [NAME]    Start MariaDB and open a SQL shell on librenms (or NAME)
  as CMD...    Run CMD in $SRC as the librenms user, e.g. \`librenms-scanctl as ./lnms device:poll linux\`
  setup        (Build time only) create the databases and sample data

Every account's password is \`$PASSWORD\`.
  admin        role admin
  reader       role global-read
  user         role user, with access to the device \`linux\` only
  user2        role user, with access to no device
API tokens (header \`X-Auth-Token\`) are in $ETCDIR/USERNAME.token.

Devices: linux, ios and routeros, answered by snmpsim on $SNMPSIM_ENDPOINT from
$SRC/tests/snmpsim/NAME.snmprec (the SNMP community is the file name).

Files:
  $SRC/.env                 database and application settings
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
    echo "librenms-scanctl: MariaDB did not start; see $LOGDIR/mariadb.log" 1>&2
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
    # --daemonize returns once snmpsim answers
    as_librenms .python_venvs/snmpsim/bin/snmpsim-command-responder-lite --daemonize \
        --pid-file="$RUNDIR/snmpsim.pid" --data-dir=tests/snmpsim --agent-udpv4-endpoint="$SNMPSIM_ENDPOINT" \
        --log-level=error --logging-method="file:$LOGDIR/snmpsim.log"
}

web_start () {
    pid_running "$RUNDIR/web.pid" && return 0
    rundirs
    (cd "$SRC" && PHP_CLI_SERVER_WORKERS=4 setsid runuser -u librenms -- \
        php artisan serve --host="$HOST" --port="$PORT" >>"$LOGDIR/web.log" 2>&1 </dev/null &
     echo $! > "$RUNDIR/web.pid")
    for i in $(seq 1 60); do
        curl -s -o /dev/null "$SITE/login" && return 0
        sleep 0.5
    done
    echo "librenms-scanctl: the web UI did not start; see $LOGDIR/web.log" 1>&2
    exit 1
}

stop_pid () {
    # the pid is a session leader (setsid) or a daemon: signal its whole process group
    pid_running "$1" && kill -- "-$(ps -o pgid= -p "$(cat "$1")" | tr -d ' ')" 2>/dev/null
    rm -f "$1"
}

seed () {
    mariadb -e "DROP DATABASE IF EXISTS librenms; CREATE DATABASE librenms CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci" \
        && as_librenms php artisan migrate --force --seed --no-interaction \
        && mkdir -p "$ETCDIR" && chown librenms:librenms "$ETCDIR" \
        && as_librenms php /usr/local/lib/librenms-scan/seed.php "$PASSWORD" "$ETCDIR"
}

cmd_poll () {
    db_start
    snmpsim_start
    for device in linux ios routeros; do
        as_librenms ./lnms device:discover "$device" --no-interaction
        as_librenms ./lnms device:poll "$device" --no-interaction
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
    # the test suite expects its database to be migrated, as CI does
    (cd "$SRC" && DB_DATABASE="$TESTDB" runuser -u librenms -- php artisan migrate --force --no-interaction)
    db_stop
}

cmd_status () {
    if db_running; then echo "MariaDB: running"; else echo "MariaDB: stopped"; fi
    if pid_running "$RUNDIR/snmpsim.pid"; then echo "snmpsim: $SNMPSIM_ENDPOINT"; else echo "snmpsim: stopped"; fi
    if pid_running "$RUNDIR/web.pid"; then echo "web UI: $SITE/"; else echo "web UI: stopped"; fi
}

cmd=${1:-help}
shift
case "$cmd" in
setup)  cmd_setup;;
start)  db_start; snmpsim_start; web_start
        echo "LibreNMS is serving $SITE/"
        echo "Every account's password is $PASSWORD; \`librenms-scanctl help\` lists accounts";;
stop)   stop_pid "$RUNDIR/web.pid"; stop_pid "$RUNDIR/snmpsim.pid"; db_stop;;
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

# Create the databases and the sample data, then shut MariaDB down cleanly so its data directory is part of the image.
RUN librenms-scanctl setup

# Discover and poll the sample devices once, so the instance has ports, sensors and RRD files. Not fatal.
RUN librenms-scanctl poll > /var/log/librenms-scan-poll.log 2>&1 \
    || echo "WARNING: the sample devices could not be polled; see /var/log/librenms-scan-poll.log"; \
    librenms-scanctl stop || true

# Smoke tests, so the log shows whether the image works: boot the instance once, then run the CI unit test selection
# without the per-OS tests (run those with `librenms-scanctl test --os NAME`). A failure does not abort the build.
RUN (librenms-scanctl start && curl -fsS -o /dev/null -w 'login page: HTTP %{http_code}\n' http://127.0.0.1:8000/login) \
    || echo "WARNING: the web UI smoke test failed"; \
    librenms-scanctl stop || true
RUN timeout 30m librenms-scanctl test \
    || echo "WARNING: the unit tests reported failures or ran out of time"; \
    librenms-scanctl stop || true
