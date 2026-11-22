#!/bin/bash
# gen.sh MODE WORKERS [cache]  -> nginx.conf on stdout
MODE=$1; W=${2:-1}; CACHE=${3:-}
if [ "$MODE" = pool ]; then M="stateless off; connections 3;"; else M=""; fi
B='dc=example,dc=org'
common() { echo "binddn \"cn=admin,$B\"; binddn_passwd \"admin\"; group_attribute member; group_attribute_is_dn on; connect_timeout 3s; bind_timeout 3s; request_timeout 6s; $M"; }
U() { echo "url $1/$B?uid?sub?(objectClass=inetOrgPerson);"; }
cat <<EOF
daemon off; worker_processes $W; user nginx; error_log /dev/stderr info; pid /tmp/n.pid;
events { worker_connections 256; }
http {
  access_log off;
  ${CACHE:+auth_ldap_cache_enabled on; auth_ldap_cache_expiration_time 600s; auth_ldap_cache_size 1000;}
  ldap_server valid   { $(U ldap://ldap.example.org:389) $(common) require valid_user; set_auth_header X-Auth-User \$remote_user; search_attributes givenName mail; attribute_header_prefix "X-LDAP-"; }
  ldap_server admins  { $(U ldap://ldap.example.org:389) $(common) require group "cn=admins,ou=groups,$B"; }
  ldap_server vpn     { $(U ldap://ldap.example.org:389) $(common) require group "cn=vpn,ou=groups,$B"; }
  ldap_server allof   { $(U ldap://ldap.example.org:389) $(common) require group "cn=admins,ou=groups,$B"; require group "cn=vpn,ou=groups,$B"; satisfy all; }
  ldap_server anyof   { $(U ldap://ldap.example.org:389) $(common) require group "cn=vpn,ou=groups,$B"; require user "uid=bob,$B"; satisfy any; }
  ldap_server onlybob { $(U ldap://ldap.example.org:389) $(common) require user "uid=bob,$B"; }
  ldap_server tls_off   { $(U ldaps://ldap.example.org:636) $(common) require valid_user; ssl_check_cert off; }
  ldap_server tls_full  { $(U ldaps://ldap.example.org:636) $(common) require valid_user; ssl_check_cert full; ssl_ca_file /ca.crt; }
  ldap_server tls_chain { $(U ldaps://ldap.example.org:636) $(common) require valid_user; ssl_check_cert chain; ssl_ca_file /ca.crt; }
  ldap_server tls_noca  { $(U ldaps://ldap.example.org:636) $(common) require valid_user; ssl_check_cert chain; }
  ldap_server tls_badhost { $(U ldaps://ldapsrv:636) $(common) require valid_user; ssl_check_cert full; ssl_ca_file /ca.crt; }
  ldap_server denyfirst { $(U ldap://ldap.example.org:389) $(common) require user "uid=nobody,$B"; }
  ldap_server dead    { $(U ldap://ldap.example.org:3899) $(common) require valid_user; max_down_retries 1; }
  server { listen 8081; location / { return 200 "backend\n"; } }
  server {
    listen 80;
    location /valid    { auth_ldap "x"; auth_ldap_servers valid;   proxy_pass http://127.0.0.1:8081; }
    location /admins   { auth_ldap "x"; auth_ldap_servers admins;  proxy_pass http://127.0.0.1:8081; }
    location /vpn      { auth_ldap "x"; auth_ldap_servers vpn;     proxy_pass http://127.0.0.1:8081; }
    location /allof    { auth_ldap "x"; auth_ldap_servers allof;   proxy_pass http://127.0.0.1:8081; }
    location /anyof    { auth_ldap "x"; auth_ldap_servers anyof;   proxy_pass http://127.0.0.1:8081; }
    location /onlybob  { auth_ldap "x"; auth_ldap_servers onlybob; proxy_pass http://127.0.0.1:8081; }
    location /tls_off  { auth_ldap "x"; auth_ldap_servers tls_off;  proxy_pass http://127.0.0.1:8081; }
    location /tls_full { auth_ldap "x"; auth_ldap_servers tls_full; proxy_pass http://127.0.0.1:8081; }
    location /tls_chain{ auth_ldap "x"; auth_ldap_servers tls_chain;proxy_pass http://127.0.0.1:8081; }
    location /tls_noca { auth_ldap "x"; auth_ldap_servers tls_noca; proxy_pass http://127.0.0.1:8081; }
    location /tls_badhost { auth_ldap "x"; auth_ldap_servers tls_badhost; proxy_pass http://127.0.0.1:8081; }
    location /dead     { auth_ldap "x"; auth_ldap_servers dead;    proxy_pass http://127.0.0.1:8081; }
    location /failover_deny { auth_ldap "x"; auth_ldap_servers denyfirst valid; proxy_pass http://127.0.0.1:8081; }
    location /failover { auth_ldap "x"; auth_ldap_servers dead valid; proxy_pass http://127.0.0.1:8081; }
  }
}
EOF
