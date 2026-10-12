# LibreNMS threat model

## What this project does and where untrusted input enters

LibreNMS is a network monitoring system. It has a PHP (Laravel) web application and a REST API, and it stores its data
in MariaDB or MySQL. Its pollers query network devices with SNMP and store time series in RRD files. LibreNMS also
evaluates alert rules and sends notifications. Most installations are in a management network. But many users of an
organization can usually reach the web UI, and some installations are open to the Internet.

The principals, from the least privileged to the most privileged:

- **Unauthenticated visitor.** This visitor can reach only the login page, the password reset, and the small number
  of endpoints that are public.
- **Monitored device, or a system that can answer for a device.** A device is not a user, but it is a primary source
  of untrusted data. This data includes SNMP responses (sysDescr, sysName, interface descriptions, sensor names, LLDP
  and CDP neighbor strings), syslog messages, and SNMP traps. It also includes the output of agent scripts and
  applications. The operator of a device must not get access to the LibreNMS server through these values. The operator
  must also not get access to the browser of a different user.
- **Normal user (role `user`).** This user sees only the devices, ports, and bills that an administrator gave access
  to. This user must not read or change other data. This rule applies to graphs, searches, AJAX tables, exports, maps,
  and the API.
- **Global read (role `global-read`).** This user reads all data and changes nothing.
- **API token.** A token acts as its user. A token must never have more rights than that user.
- **Administrator (role `admin`).** Trusted. Refer to "Anything to leave alone".
- **Server operator.** Fully trusted. The operator controls the filesystem, `.env`, `config.php`, the database, and
  the `lnms` command line.

Untrusted input enters through these paths:

- each web page and AJAX endpoint
- the API (`/api/v0`)
- all data that a device reports
- the syslog and SNMP trap receivers
- the authentication backends (LDAP, Active Directory, RADIUS, SSO, and HTTP headers)
- data from other systems (Oxidized, PeeringDB, plugins)

## Components that matter most / least

The most important components:

- **Authorization.** `app/Policies/`, `app/Http/Middleware/`, and `LibreNMS/Cache/PermissionsCache.php`. The legacy
  code has its own checks for each device and each port: `device_permitted`, `port_permitted`, and `bill_permitted` in
  `includes/html/functions.inc.php`.
- **Legacy web code.** `includes/html/` (pages, `forms/`, `table/`, `graphs/`) and the entry points in `html/`
  (`ajax_form.php`, `ajax_table.php`, `graph.php`, and others). This code is older than the Laravel code. Some of this
  code builds SQL and HTML by hand. Missing permission checks, SQL injection, and XSS are most probable here.
- **Laravel controllers and API.** `app/Http/Controllers/`, `routes/`, and `includes/html/api_functions.inc.php`.
- **Command execution.** LibreNMS runs `rrdtool`, `snmpget`, `snmpwalk`, `fping`, service checks (Nagios plugins),
  and other programs. A value can come from a device, a user, or the database. Each value that goes into a
  command line, an rrdtool command stream, or a file path must be safe. The related code is in
  `LibreNMS/Data/Store/Rrd.php`, `app/Facades/Rrd.php`, `includes/html/graphs/`, `LibreNMS/Data/Source/`,
  `includes/services.inc.php`, and `check-services.php`.
- **Stored XSS from device data.** LibreNMS stores the strings that a device reports. Then it shows these strings to
  each user who can see the device. The code that stores them is in `includes/discovery/`, `includes/polling/`,
  `LibreNMS/OS/`, and `LibreNMS/Modules/`. The views that print them are in `resources/views/` and `includes/html/`.
- **Authentication and sessions.** `LibreNMS/Authentication/` (LDAP, Active Directory, RADIUS, SSO, HTTP auth,
  two-factor authentication), `app/Http/Controllers/Auth/`, and the API token code in
  `app/Providers/AppServiceProvider.php`.
- **Alerting.** `LibreNMS/Alerting/` and `LibreNMS/Alert/` build the rules and generate SQL. Administrators write the
  alert templates as Blade templates. The transports in `LibreNMS/Alert/Transport/` make outbound requests and run
  mailers with values that come from devices.
- **Syslog and trap handlers.** `syslog.php`, `snmptrap.php`, `LibreNMS/Snmptrap/`, and `app/Http/Controllers/Api/`.
- **Secrets.** SNMP communities, SNMPv3 keys, API tokens, transport credentials, and the application key are secrets.
  A user without the necessary right must not see them. This rule applies to pages, API responses, exports, logs, and
  debug output.

The less important components:

- `doc/`, `tests/`, and `scripts/` (the operator runs these scripts)
- `mibs/` (third-party MIB files) and `vendor/`
- the bundled JavaScript libraries in `html/js/` and `html/build/`. For a vulnerable version of a third-party library,
  write one short note and no analysis.
- the OS definitions in `resources/definitions/`. When one of their values goes into a command or a query, they are
  in scope.

## How to exercise it

The image has no network. When the container starts, no service runs. The checkout is in `/src`, and the user
`librenms` owns it. `lnms` does not run as root, so run each LibreNMS command as the user `librenms`.

Start the database and the web UI with these commands:

```sh
service mariadb start
runuser -u librenms -- php artisan serve --no-reload > /tmp/web.log 2>&1 &    # http://127.0.0.1:8000/
```

The instance has three accounts. **The password of each account is `LibreNMS-scan-1234`.**

- `admin`: role `admin`
- `reader`: role `global-read`
- `user`: role `user`, with access to no device

To get an API token for an account, use `lnms api:token-create`. Send the token in the header `X-Auth-Token`:

```sh
runuser -u librenms -- ./lnms api:token-create user
curl -H "X-Auth-Token: TOKEN" http://127.0.0.1:8000/api/v0/devices
```

The instance has no devices. `lnms dev:simulate` starts snmpsim on `127.1.6.1:1161` and adds a device. snmpsim uses
the recordings `tests/snmpsim/NAME.snmprec`, and the SNMP community selects the recording. To add the device `linux`
and get its data, use these commands:

```sh
runuser -u librenms -- ./lnms dev:simulate --multiple linux > /tmp/simulate.log 2>&1 &
runuser -u librenms -- ./lnms device:discover linux
runuser -u librenms -- ./lnms device:poll linux
```

`dev:simulate` adds one device for each run. To add a second device, stop snmpsim, then start `dev:simulate` with
a different name. The first device stays in the database, and one snmpsim answers for all recordings:

```sh
pkill -u librenms -f snmpsim
runuser -u librenms -- ./lnms dev:simulate --multiple ios > /tmp/simulate.log 2>&1 &
```

To give `user` access to a device, log in to the web UI as `admin` and edit the user. If `user` then gets access to
a different device, that access goes across the primary boundary between users.

To act as a hostile device, do these steps:

1. Copy a recording to `tests/snmpsim/evil.snmprec`.
2. Edit the copy. For example, put markup or shell metacharacters in sysDescr, sysName, or ifAlias.
3. Start `lnms dev:simulate --multiple evil`.
4. Discover the device.
5. Poll the device.

The RRD files are in `/src/rrd`. The application log is `/src/logs/librenms.log`. `mariadb librenms` opens an SQL
shell on the live database.

The tests use a different database:

```sh
runuser -u librenms -- ./lnms dev:check unit --db --snmpsim                 # tests for the changed files
runuser -u librenms -- ./lnms dev:check unit --db --snmpsim --os linux      # discovery and polling tests for one OS
runuser -u librenms -- env DBTEST=1 vendor/bin/phpunit tests/Unit/SqliteTest.php
```

The developer documentation is in `doc/Developing/`. The API documentation is in `doc/API/`.

## How you rate severity

- **Critical:**
  - An unauthenticated visitor, a normal user, or a monitored device causes one of these results: code or command
    execution on the server, SQL injection, or the read or write of an arbitrary file on the server.
  - Authentication bypass.
  - Account takeover without an action from the victim.
- **High:**
  - A normal user or a global-read user becomes an administrator.
  - A normal user reads or changes many devices, ports, or bills without access to them.
  - A user who is not an administrator reads stored credentials (SNMP communities, SNMPv3 keys, API tokens, transport
    secrets).
  - A device or a normal user stores XSS that runs for an administrator in normal use.
  - A user who is not an administrator causes server-side request forgery that reaches internal services.
- **Medium:**
  - A small leak or a small unauthorized change (one device, one field).
  - Stored XSS that needs an unusual action from the victim.
  - Reflected XSS.
  - A state-changing action without CSRF protection.
  - One request that uses a large quantity of CPU or memory.
- **Low:**
  - A leak of data that the viewer can get by a different method.
  - A problem that needs an improbable configuration.

If only an administrator can cause a finding, rate it two levels lower than the same finding from a normal user. Code
execution by an administrator through a documented feature is not a finding. Refer to the next section.

## Anything to leave alone

- **Administrators are trusted.** They can add devices, set the paths of external programs, and write alert templates
  and transports. They can also configure service checks and install plugins. Each of these features is a documented
  method to run code or to make requests from the server. If an administrator-only problem goes across a boundary
  that an administrator does not control, report it. Examples are XSS against a different administrator, and CSRF
  that makes an administrator do the action. Do not report other administrator-only problems.
- The configuration that the server operator sets, and command-line tools with arguments that the operator selects.
- The configuration of this image: `php artisan serve`, the MariaDB configuration, and the sample passwords.
- Volumetric denial of service, brute force, and missing rate limits.
- Self-XSS, and attacks that damage only the session of the attacker.
- `tests/`, `doc/`, `mibs/`, `vendor/`, and other third-party code.

## Reports and patches

- Give the principal, the boundary, and the call chain from the entry point to the sink.
- If possible, include a reproducer for the instance in this image. A reproducer can be HTTP requests, or an edited snmprec
  recording with the poll command.
- Keep each patch small, and use the style of the adjacent code.
- In new code, use Laravel (Eloquent, policies, Blade escaping, request validation). Do not add new uses of the legacy
  `db*` helpers.
- If a regression test is practical, include one in `tests/`.
- Report each root cause one time. The legacy code repeats patterns in many files (for example, each file in
  `includes/html/table/` or `includes/html/forms/`). If the same flaw is in more than one file, send one report that
  lists all affected files.
- The image contains the git history. If you can find the commit or release that introduced the flaw, give it. Only
  the latest monthly release and the daily release (`master`) get security fixes.
