# LDAP Authentication module for nginx

LDAP module for nginx which supports authentication against multiple LDAP servers.

## Features

- Multiple LDAP server support with failover
- User/group membership authorization (`require user`, `require group`, `require valid_user`, `satisfy all|any`)
- LDAP attribute fetching (injected as HTTP headers)
- **Stateless mode** — connect on-demand, no persistent connections (default)
- **Connection pool mode** — persistent connections for high-throughput
- **Custom header injection** — `set_auth_header` with nginx variable support
- Authentication result caching
- DNS resolver fallback for LDAP hostname resolution
- LDAPS (TLS) with certificate verification
- Base64/hex-encoded bind passwords

## How to install

### FreeBSD

```bash
cd /usr/ports/www/nginx && make config install clean
```
Check HTTP_AUTH_LDAP option.

### Linux

```bash
git clone https://github.com/Ericbla/nginx-auth-ldap.git
cd nginx-source
./configure --add-module=/path/to/nginx-auth-ldap
make install
```

## Quick start (stateless, recommended)

```nginx
http {
    auth_ldap_cache_enabled on;
    auth_ldap_cache_expiration_time 10m;
    auth_ldap_cache_size 500;

    ldap_server my_ldap {
        url ldap://ldap.example.com:389/DC=example,DC=com?uid?sub?(objectClass=person);
        binddn "CN=svc-nginx,OU=ServiceAccounts,DC=example,DC=com";
        binddn_passwd "s3cret";
        group_attribute member;
        group_attribute_is_dn on;
        require valid_user;
        search_attributes mail displayName department;

        # Tight timeouts for stateless mode
        connect_timeout 3s;
        bind_timeout 2s;
        request_timeout 5s;

        # Inject custom headers on auth success
        set_auth_header X-Auth-User $remote_user;
        set_auth_header X-Auth-Role editor;
    }

    server {
        listen 80;

        location /private {
            auth_ldap "Restricted Area";
            auth_ldap_servers my_ldap;
            proxy_pass http://backend;
        }
    }
}
```

## Connection modes

### Stateless (default)

Connects to LDAP on each request, closes immediately after. No idle connections, no health checks needed, zero load on LDAP server between requests. Good for most use cases.

```nginx
ldap_server my_ldap {
    url ldap://...;
    stateless on;   # optional, this is the default
}
```

### Connection pool

Pre-establishes persistent connections at startup. Lower latency per request but holds connections open. Use for high-traffic endpoints.

```nginx
ldap_server my_ldap {
    url ldap://...;
    stateless off;
    connections 5;  # pool size per worker
}
```

## Available config parameters

### Main context (http)

#### auth_ldap_cache_enabled

> **Syntax:** `auth_ldap_cache_enabled on | off;`
> **Default:** `off`
> **Context:** `http`

Enable caching of authentication results.

#### auth_ldap_cache_expiration_time

> **Syntax:** `auth_ldap_cache_expiration_time time;`
> **Default:** `10s`
> **Context:** `http`

Cache entry TTL. When cached, subsequent identical requests skip LDAP entirely.

#### auth_ldap_cache_size

> **Syntax:** `auth_ldap_cache_size size;`
> **Default:** `100`
> **Context:** `http`

Number of cached entries (minimum 100).

#### auth_ldap_servers_size

> **Syntax:** `auth_ldap_servers_size size;`
> **Default:** `7`
> **Context:** `http`

Maximum number of `ldap_server` definitions allowed.

#### auth_ldap_resolver

> **Syntax:** `auth_ldap_resolver address ... [valid=time] ...;`
> **Default:** `--`
> **Context:** `http`

DNS resolver for fallback when system resolver cannot resolve the LDAP hostname.

#### auth_ldap_resolver_timeout

> **Syntax:** `auth_ldap_resolver_timeout time;`
> **Default:** `10s`
> **Context:** `http`

Resolver query timeout.

### Location/server context

#### auth_ldap

> **Syntax:** `auth_ldap realm | off;`
> **Default:** `--`
> **Context:** `http, server, location, limit_except`

Enables LDAP authentication with the given realm string (shown in browser auth dialog).

#### auth_ldap_servers

> **Syntax:** `auth_ldap_servers name [name ...];`
> **Default:** `--`
> **Context:** `http, server, location, limit_except`

Selects which `ldap_server` definitions to use. Multiple servers are tried in order (failover).

### `ldap_server` block

#### url

> **Syntax:** `url ldap[s]://host[:port]/base_dn?attr?scope?filter;`
> **Default:** `--`
> **Required:** yes

LDAP server URL. Format: `ldap[s]://host[:port]/dn?attrs?scope?filter[?exts]`.

#### binddn

> **Syntax:** `binddn dn;`
> **Default:** `--`

DN for the initial (master) bind.

#### binddn_passwd

> **Syntax:** `binddn_passwd password [text | base64 | hex];`
> **Default:** `--`

Password for the master bind. Supports `text` (default), `base64`, or `hex` encoding.

#### stateless

> **Syntax:** `stateless on | off;`
> **Default:** `on`

`on`: Connect on each request, close after use. No persistent connections.
`off`: Pre-establish persistent connections at startup (pool mode). Use `connections` to set pool size.

#### connections

> **Syntax:** `connections count;`
> **Default:** `1`
> **Context:** `ldap_server`

Number of parallel connections to this LDAP server (pool mode only, `stateless off`).

#### set_auth_header

> **Syntax:** `set_auth_header name value;`
> **Default:** `--`
> **Context:** `ldap_server`

Injects an HTTP response header on successful authentication. `value` supports nginx variables (`$remote_user`, `$http_*`, etc.). Repeatable.

```nginx
set_auth_header X-Auth-User $remote_user;
set_auth_header X-Auth-Role viewer;
set_auth_header X-Request-ID $request_id;
```

#### require

> **Syntax:** `require valid_user [dn] | require user dn | require group dn;`
> **Default:** `--`

- `require valid_user` — any valid LDAP user passes
- `require valid_user dn_template` — use `dn_template` as the user DN (nginx variables supported)
- `require user dn` — user DN must match (repeatable)
- `require group dn` — user must belong to this group (repeatable)

#### satisfy

> **Syntax:** `satisfy all | any;`
> **Default:** `--`

`all`: all `require` rules must match.
`any`: any single `require` rule match is sufficient.

#### group_attribute

> **Syntax:** `group_attribute attr;`
> **Default:** `--`

LDAP attribute containing group members (e.g. `member`, `uniqueMember`).

#### group_attribute_is_dn

> **Syntax:** `group_attribute_is_dn on | off;`
> **Default:** `off`

If `on`, the user's full DN is used when checking group membership. If `off`, just the username.

#### search_attributes

> **Syntax:** `search_attributes attr1 [attr2 ... attrN];`
> **Default:** `--`

LDAP attributes to fetch during the user search. Each value is injected as an HTTP response header with the configured prefix.

#### attribute_header_prefix

> **Syntax:** `attribute_header_prefix string;`
> **Default:** `X-LDAP-ATTR-`

Prefix for response headers carrying fetched LDAP attributes. Example: with prefix `X-LDAP-ATTR-` and attribute `mail`, the header is `X-LDAP-ATTR-mail`.

#### referral

> **Syntax:** `referral on | off;`
> **Default:** `on`

Enable or disable LDAP referral following.

#### ssl_check_cert

> **Syntax:** `ssl_check_cert on | full | chain | off;`
> **Default:** `off`

Verify the remote certificate for LDAPS connections. Requires OpenSSL >= 1.0.2.
- `on` / `full`: verify chain + hostname
- `chain`: verify chain only (skip hostname check)
- `off`: no verification

#### ssl_ca_file

> **Syntax:** `ssl_ca_file path;`
> **Default:** `--`

Path to CA certificate file for LDAPS verification.

#### ssl_ca_dir

> **Syntax:** `ssl_ca_dir path;`
> **Default:** `--`

Path to CA certificate directory (requires `c_rehash`).

#### clean_on_timeout

> **Syntax:** `clean_on_timeout on | off;`
> **Default:** `off`

If `on`, destroy and reconnect an LDAP connection after a request timeout instead of returning it to the pool.

#### max_down_retries

> **Syntax:** `max_down_retries number;`
> **Default:** `0`

Number of reconnection attempts after `LDAP_SERVER_DOWN` errors before giving up.

#### Timeouts

All accept nginx time syntax (`s`, `m`, `h`, `d`, etc.):

| Directive | Default | Description |
|-----------|---------|-------------|
| `connect_timeout` | `10s` | TCP connect + TLS handshake |
| `bind_timeout` | `5s` | LDAP bind response wait |
| `request_timeout` | `10s` | Total auth flow (search + bind + rebind) |
| `reconnect_timeout` | `10s` | Delay before reconnection (pool mode) |

## Testing

```bash
make test-unit       # Run C unit tests (24 tests)
make check-leaks     # Run with valgrind leak detection
make test            # Run all tests
make clean           # Clean build artifacts
```

Test files:
- `test/unit/test_utils.c` — utility function tests (sanitize, hex decode, array operations)
- `test/unit/test_cache.c` — cache hit/miss/eviction/expiration/attribute tests
- `t/001-auth.t` — integration tests with MockLDAP and valgrind checks
- `t/lib/MockLDAP.pm` — minimal mock LDAP server for testing
- `.github/workflows/test.yml` — CI pipeline
