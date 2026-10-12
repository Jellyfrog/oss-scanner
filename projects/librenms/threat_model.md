# LibreNMS threat model

## What this project does and where untrusted input enters

LibreNMS is a network monitoring system: a PHP (Laravel) web application and REST API backed by MariaDB/MySQL, with
pollers that query network devices over SNMP, store time series in RRD files, evaluate alert rules and send
notifications. It is usually installed inside a management network, but the web UI is often reachable by many users of
an organisation and sometimes from the Internet.

Principals, from least to most privileged:

- **Unauthenticated visitor.** May only reach the login page, password reset, and the few endpoints that are meant to
  be public.
- **Monitored device or anything that can answer for one.** Not a user, but a major source of untrusted data: SNMP
  responses (sysDescr, sysName, interface descriptions, sensor names, LLDP/CDP neighbour strings), syslog messages,
  SNMP traps, and the output of agent scripts and applications. A device operator must not gain anything on the
  LibreNMS server or in another user's browser through these values.
- **Normal user (role `user`).** Sees only the devices, ports and bills they were given access to. Must not read or
  change anything else, including through graphs, searches, AJAX tables, exports, maps or the API.
- **Global read (role `global-read`).** Reads everything, changes nothing.
- **API token.** Acts as its user and must never exceed that user's rights.
- **Administrator (role `admin`).** Trusted, see "Anything to leave alone".
- **Server operator.** Fully trusted: the filesystem, `.env`, `config.php`, the database and the `lnms` command line.

Untrusted input enters through every web page and AJAX endpoint, the API (`/api/v0`), everything a device reports,
syslog and SNMP trap receivers, authentication backends (LDAP, Active Directory, RADIUS, SSO and HTTP headers), and
data fetched from other systems (Oxidized, PeeringDB, plugins).

## Components that matter most / least

Most important:

- Authorization: `app/Policies/`, `app/Http/Middleware/`, `LibreNMS/Cache/PermissionsCache.php`, and the per-device and per-port
  checks in legacy code (`device_permitted`, `port_permitted`, `bill_permitted` in `includes/html/`).
- Legacy web code: `includes/html/` (pages, `forms/`, `table/`, `graphs/`) and the entry points in `html/`
  (`ajax_form.php`, `ajax_table.php`, `graph.php` and others). It predates the Laravel code, builds SQL and HTML by
  hand in places, and is where missing permission checks, SQL injection and XSS are most likely.
- Laravel controllers and API: `app/Http/Controllers/`, `routes/`, `includes/html/api_functions.inc.php`.
- Command execution. LibreNMS runs `rrdtool`, `snmpget`/`snmpwalk`, `fping`, `nmap`, service checks (Nagios plugins)
  and other programs. Any value from a device, a user or the database that reaches a command line, an rrdtool
  command stream or a file path must be safe: `LibreNMS/Data/Store/Rrd.php`, `app/Facades/Rrd.php`,
  `includes/html/graphs/`, `LibreNMS/Data/Source/`, `includes/services.inc.php`, `check-services.php`.
- Stored XSS from device data. Strings reported by a device are stored and later shown to every user who can see the
  device: `includes/discovery/`, `includes/polling/`, `LibreNMS/OS/`, `LibreNMS/Modules/`, and the views that print
  them (`resources/views/`, `includes/html/`).
- Authentication and sessions: `LibreNMS/Authentication/` (LDAP, Active Directory, RADIUS, SSO, HTTP auth, two-factor
  authentication), `app/Http/Controllers/Auth/`, API token handling in `app/Providers/AppServiceProvider.php`.
- Alerting: rule building and SQL generation (`LibreNMS/Alerting/`, `LibreNMS/Alert/`), templates (Blade templates
  written by administrators), and transports in `LibreNMS/Alert/Transport/`, which make outbound requests and run
  mailers with values that come from devices.
- Syslog and trap handlers: `syslog.php`, `snmptrap.php`, `LibreNMS/Snmptrap/`, `app/Http/Controllers/Api/`.
- Secrets at rest and in output: SNMP communities and SNMPv3 keys, API tokens, transport credentials and the
  application key must not reach users who lack the right to see them (pages, API responses, exports, logs, debug
  output).

Less important: `doc/`, `tests/`, `scripts/` (run by the operator), `mibs/` (third-party MIB files), `vendor/` and
bundled JavaScript libraries in `html/js/` and `html/build/` (third-party; a vulnerable version is worth one short
note, not an analysis), and the OS definitions in `resources/definitions/` except where a value from them reaches a
command or a query.

## How to exercise it

The image has no network and no running services. Start them with:

```sh
librenms-scanctl start      # MariaDB, snmpsim and the web UI on http://127.0.0.1:8000/
librenms-scanctl help       # all commands, accounts and file locations
```

The checkout is in `/src` and belongs to the user `librenms`; the web UI and all LibreNMS commands run as that user.
Run a command as that user with `librenms-scanctl as CMD`, for example `librenms-scanctl as ./lnms device:poll linux`.

**Every account's password is `LibreNMS-scan-1234`.**

- `admin`: role `admin`
- `reader`: role `global-read`
- `user`: role `user`, with access to the device `linux` only
- `user2`: role `user`, with access to no device

`user` reaching the devices `ios` or `routeros`, or `user2` reaching any device, crosses the main boundary between
users.

An API token for each account is in `/etc/librenms-scan/USERNAME.token`:

```sh
curl -H "X-Auth-Token: $(cat /etc/librenms-scan/user.token)" http://127.0.0.1:8000/api/v0/devices
```

The three devices `linux`, `ios` and `routeros` are answered by snmpsim on `127.1.6.1:1161` from the recordings
`tests/snmpsim/NAME.snmprec`; the SNMP community selects the recording. To act as a hostile device, copy and edit a
recording (for example put markup or shell metacharacters in sysDescr, sysName or ifAlias), add a device that uses it
as the community, and discover and poll it:

```sh
librenms-scanctl as ./lnms dev:simulate --help        # how the test suite adds simulated devices
librenms-scanctl as ./lnms device:discover linux
librenms-scanctl as ./lnms device:poll linux
```

RRD files are in `/src/rrd`, the application log is `/src/logs/librenms.log`, and other logs are in
`/var/log/librenms-scan`. `librenms-scanctl reset` rebuilds the database and the sample data; `librenms-scanctl db`
opens a SQL shell.

The tests use a separate database:

```sh
librenms-scanctl test                                 # the CI selection without the per-OS tests
librenms-scanctl test --os linux                      # discovery and polling tests for one OS
librenms-scanctl phpunit tests/Feature/SomeTest.php   # one file, with database tests enabled
```

Developer documentation is in `doc/Developing/`, and the API documentation is in `doc/API/`.

## How you rate severity

- **Critical:** code or command execution, SQL injection, or arbitrary file read or write on the server by an
  unauthenticated visitor, by a normal user, or by a monitored device; authentication bypass; account takeover without
  interaction.
- **High:** a normal or global-read user becomes an administrator; a normal user reads or changes devices, ports or
  bills they have no access to on a large scale; a non-administrator reads stored credentials (SNMP communities,
  SNMPv3 keys, API tokens, transport secrets); stored XSS that a device or a normal user can plant and that runs for
  an administrator during normal use; server-side request forgery by a non-administrator that reaches internal
  services.
- **Medium:** a limited leak or a limited unauthorized change (one device, one field); stored XSS that needs an
  unusual action from the victim; reflected XSS; missing CSRF protection on a state-changing action; a single
  request that uses much CPU or memory.
- **Low:** leaks of information the viewer can get in another way, and issues that need an unlikely configuration.

Findings that only an administrator can trigger are rated two levels lower than the same finding from a normal user,
and code execution by an administrator through a documented feature is not a finding (see below).

## Anything to leave alone

- **Administrators are trusted.** They can add devices, set the paths of external programs, write alert templates
  and transports, configure service checks and install plugins. Each of these is a documented way to run code or to
  make requests from the server. Report an administrator-only issue only when it crosses a boundary an administrator
  does not already control, for example reflected or stored XSS against another administrator, or CSRF that makes an
  administrator do it.
- The server operator's configuration and the command-line tools run with arguments the operator chose.
- The configuration of this image: `php artisan serve`, the MariaDB settings, the sample passwords and tokens, and
  `/usr/local/bin/librenms-scanctl`.
- Volumetric denial of service, brute force and missing rate limits.
- Self-XSS and attacks that only harm the attacker's own session.
- `tests/`, `doc/`, `mibs/`, `vendor/` and other third-party code.

## Reports and patches

- Name the principal, the boundary that is crossed and the call chain from the entry point to the sink. A reproducer
  against the sample instance (HTTP requests, or an edited snmprec recording plus the poll command) is ideal.
- Keep patches minimal and in the style of the surrounding code. New code should use Laravel (Eloquent, policies,
  Blade escaping, request validation) and not extend the legacy `db*` helpers.
- Include a regression test under `tests/` where one is practical.
- Report one root cause once. The legacy code repeats patterns across many files (for example each file in
  `includes/html/table/` or `includes/html/forms/`): when the same flaw appears in several of them, send one report
  that lists every affected file and not one report for each file.
- The image keeps the git history. Say which commit or release introduced the flaw when you can find it: only the
  latest monthly release and the daily (master) release get security fixes.
