#!/bin/bash
# nginx -t on good and bad ldap_server blocks: a bad one must be refused with a message, never crash.
# Usage: IMG=<image whose nginx has the module> test/integration/config.sh
IMG=${IMG:?set IMG to an image whose nginx includes the module}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
PASS=0; FAILN=0
check() { # name want(ok|rej) body [message regex]
  printf 'daemon off; user nginx; events{} http { ldap_server s { %s } server { listen 8080; location / { auth_ldap "x"; auth_ldap_servers s; } } }\n' "$3" > $W/nginx.conf
  out=$(docker run --rm -v $W/nginx.conf:/etc/nginx/nginx.conf:ro --entrypoint nginx $IMG -t 2>&1); rc=$?
  if [ "$2" = ok ]; then good=$([ $rc = 0 ] && echo 1); else good=$([ $rc = 1 ] && [[ "$out" =~ ${4:-emerg} ]] && echo 1); fi
  if [ -n "$good" ]; then PASS=$((PASS+1)); printf '  ok   %-30s %s\n' "$1" "$2"; else FAILN=$((FAILN+1)); printf '  FAIL %-30s want %s (rc=%s): %s\n' "$1" "$2" "$rc" "$(echo "$out" | tail -1)"; fi
}
U='url ldap://h.example.org/dc=example,dc=org?uid?sub?(objectClass=*);'
check "valid block" ok "$U binddn cn=a,dc=x; binddn_passwd pw; require valid_user;"
check "IPv6 host" ok 'url ldap://[::1]:389/dc=x?uid?sub?(objectClass=*);'
check "valid_user DN template" ok "$U require valid_user \"uid=\$remote_user,dc=x\";"
check "no host" rej 'url ldap:///dc=x?uid?sub?(objectClass=*);' 'has no host'
check "port out of range" rej 'url ldap://h:99999/dc=x?uid?sub?(objectClass=*);' 'invalid port'
check "filter without parentheses" rej 'url ldap://h/dc=x?uid?sub?objectClass=*;' 'parenthesized'
check "two top-level filters" rej 'url ldap://h/dc=x?uid?sub?(a=b)(c=d);' 'parenthesized'
check "unknown directive" rej "$U bogus 1;" 'unknown directive'
check "invalid on/off" rej "$U stateless maybe;" 'on" or "off'
check "directive without argument" rej "$U binddn;" 'number of arguments'
check "max_down_retries not a number" rej "$U max_down_retries abc;" 'integer'
check "unknown require" rej "$U require frob x;" 'unknown "require'
check "require user without DN" rej "$U require user;" 'exactly one argument'
check "binddn without password" rej "$U binddn cn=a,dc=x;" 'without a password'
check "require group without group_attribute" rej "$U require group cn=g,dc=x;" 'group_attribute'
check "no url" rej 'binddn x;' 'no "url"'
check "invalid ssl_check_cert" rej "$U ssl_check_cert sometimes;" 'ssl_check_cert'
check "connections 0" rej "$U connections 0;" 'greater than 0'
check "bad timeout" rej "$U connect_timeout abc;" 'time unit'
printf 'daemon off; user nginx; events{} http { ldap_server s { %s } ldap_server s { %s } server { listen 8080; } }\n' "$U" "$U" > $W/nginx.conf
out=$(docker run --rm -v $W/nginx.conf:/etc/nginx/nginx.conf:ro --entrypoint nginx $IMG -t 2>&1)
if [[ "$out" =~ duplicate\ ldap_server ]]; then PASS=$((PASS+1)); echo "  ok   duplicate ldap_server name         rej"; else FAILN=$((FAILN+1)); echo "  FAIL duplicate ldap_server name: $out"; fi
echo "TOTAL ok=$PASS fail=$FAILN"; [ $FAILN = 0 ]
