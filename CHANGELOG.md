# Changelog

## [2.1.0] - unreleased

Fixes ported from the revived upstream (kvspb/nginx-auth-ldap 1.x), adapted to this fork's stateless mode.

### Security

- The login was put into the user and group search filters as sent: `*`, `(` and `)` changed the filter
  (CVE-2020-14013). Escaped now. A login such as `ali*` with alice's password was accepted as alice.
- `$remote_user` in a `require valid_user` DN template is escaped as an RDN value: a login could add RDNs.
- `satisfy all` let users through groups they were not members of; the DN of the previous group search leaked.
- A CA configured on one `ldap_server` was trusted by every other one.
- LDAPS: the IP subjectAltName check read the port bytes of the socket address; a host name is no longer
  matched against the subject CN; a missing peer certificate no longer dereferences NULL.

### Changed

- 503 instead of a dropped connection (timeout) or a 401 (LDAP down) when no server could decide; not cached.
- Stateless mode fails over to the next server at once when a connect fails.
- `nginx -t` refuses bad `ldap_server` blocks (see README, "Configuration checks"). Configurations that were
  accepted silently with a typo, an invalid on/off value or `binddn` without a password are refused now.
- `require user` compares DNs as DNs.

### Fixed

- The DN of a `require valid_user` template was not NUL-terminated when bound.
- Stateless mode: the auth cache never hit; a worker aborted on an assertion; a request kept stale pointers
  in the waiting queue.
- Cache: nothing was cached during the first ttl after start-up; the last entry of a bucket was never used;
  attribute strings leaked on every update.
- The host name of an `ldaps://` url is sent as SNI.
- Linking: the module no longer links the system OpenSSL (`config`), so it uses the one nginx is built with.
