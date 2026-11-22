#!/bin/bash
# Docker-based integration tests: nginx (with this module) against a real OpenLDAP (osixia/openldap).
# Usage: IMG=<image whose nginx has the module> test/integration/run.sh
# The image only needs nginx and curl. TLS material is generated here (the one shipped in the
# osixia image has expired). Covers stateless and pool mode, require/satisfy, LDAPS verification,
# timeouts, LDAP outages, injection attempts, the auth cache and several workers.
S=$(dirname "$(readlink -f "$0")"); IMG=${IMG:?set IMG to an image whose nginx includes the module}
W=$(mktemp -d); trap 'rm -rf "$W"; docker rm -f ngt ldapsrv >/dev/null 2>&1; docker network rm ldaptest >/dev/null 2>&1' EXIT
mkdir -p $W/pki; cd $W/pki
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj "/CN=test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout ldap.key -out ldap.csr -subj "/CN=ldap.example.org" 2>/dev/null
printf "subjectAltName=DNS:ldap.example.org\n" > ext.cnf
openssl x509 -req -in ldap.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out ldap.crt -days 2 -extfile ext.cnf 2>/dev/null
docker run --rm --entrypoint cat osixia/openldap:1.5.0 /container/service/slapd/assets/certs/dhparam.pem > dhparam.pem
chmod 644 *; cd "$S"
PASS=0; FAILN=0
docker rm -f ngt ldapsrv >/dev/null 2>&1; docker network rm ldaptest >/dev/null 2>&1; docker network create ldaptest >/dev/null
docker create --name ldapsrv --hostname ldap.example.org --network ldaptest --network-alias ldap.example.org \
  -e LDAP_ORGANISATION=ex -e LDAP_DOMAIN=example.org -e LDAP_ADMIN_PASSWORD=admin -e LDAP_TLS_VERIFY_CLIENT=never -e LDAP_TLS_CRT_FILENAME=ldap.crt -e LDAP_TLS_KEY_FILENAME=ldap.key -e LDAP_TLS_CA_CRT_FILENAME=ca.crt -e LDAP_TLS_DH_PARAM_FILENAME=dhparam.pem osixia/openldap:1.5.0 >/dev/null
docker cp $W/pki/. ldapsrv:/container/service/slapd/assets/certs/; docker start ldapsrv >/dev/null
for i in $(seq 40); do docker exec ldapsrv ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D cn=admin,dc=example,dc=org -w admin dn >/dev/null 2>&1 && break; sleep 2; done
docker cp $S/data.ldif ldapsrv:/data.ldif
docker exec ldapsrv ldapadd -x -H ldap://localhost -D cn=admin,dc=example,dc=org -w admin -f /data.ldif 2>&1 | grep -ci "adding"
cp $W/pki/ca.crt $W/ca.crt
start() { # mode workers [cache]
  docker rm -f ngt >/dev/null 2>&1; $S/gen.sh "$@" > $W/nginx.conf
  docker run -d --name ngt --network ldaptest -v $W/nginx.conf:/etc/nginx/nginx.conf:ro -v $W/ca.crt:/ca.crt:ro --entrypoint nginx $IMG >/dev/null; sleep 3
  [ "$(docker inspect -f '{{.State.Running}}' ngt)" = true ] || { echo "NGINX DID NOT START"; docker logs ngt 2>&1 | tail -3; exit 1; }
}
code() { docker exec ngt curl -s -m 20 -o /dev/null -w '%{http_code}' "$@"; }
t() { # name path creds expected-regex
  local got; if [ -n "$3" ]; then got=$(code -u "$3" localhost$2); else got=$(code localhost$2); fi
  if [[ "$got" =~ ^($4)$ ]]; then PASS=$((PASS+1)); printf '  ok   %-34s %-12s -> %s\n' "$1" "$3" "$got"; else FAILN=$((FAILN+1)); printf '  FAIL %-34s %-12s -> %s (want %s)\n' "$1" "$3" "$got" "$4"; fi; }
DENY='401|403'
scen() {
 t "valid_user alice ok" /valid alice:alicepw 200;  t "valid_user bob ok" /valid bob:bobpw 200
 t "valid_user wrong pw" /valid alice:bad "$DENY";  t "valid_user unknown" /valid nobody:x "$DENY"; t "valid_user no creds" /valid "" 401
 t "valid_user empty pw" /valid alice: "$DENY"
 t "group admins alice" /admins alice:alicepw 200;  t "group admins bob" /admins bob:bobpw 200; t "group admins carol(no)" /admins carol:carolpw "$DENY"
 t "group vpn alice" /vpn alice:alicepw 200;        t "group vpn bob(no)" /vpn bob:bobpw "$DENY"
 t "satisfy all alice" /allof alice:alicepw 200;    t "satisfy all bob(no)" /allof bob:bobpw "$DENY"
 t "satisfy any alice(vpn)" /anyof alice:alicepw 200; t "satisfy any bob(user)" /anyof bob:bobpw 200; t "satisfy any carol(no)" /anyof carol:carolpw "$DENY"
 t "require user bob" /onlybob bob:bobpw 200;       t "require user alice(no)" /onlybob alice:alicepw "$DENY"
  t "require user, DN case/spacing differs" /bobdn bob:bobpw 200; t "require user, DN case/spacing, other user" /bobdn alice:alicepw "$DENY"
  t "valid_user DN template" /tpl alice:alicepw 200; t "valid_user DN template bad pw" /tpl alice:bad "$DENY"
 t "ldaps verify off" /tls_off alice:alicepw 200;   t "ldaps verify off badpw" /tls_off alice:bad "$DENY"
 t "ldaps full + CA" /tls_full alice:alicepw 200;   t "ldaps chain + CA" /tls_chain alice:alicepw 200
 t "ldaps chain, no CA (must fail)" /tls_noca alice:alicepw '000|401|403|500|502|503'
 t "ldaps full wrong hostname (fail)" /tls_badhost alice:alicepw '000|401|403|500|502|503'
 # KNOWN LIMITATION (identical in v1.8): an unreachable first server is not skipped; the request ends after request_timeout
 t "failover: unreachable first server" /failover alice:alicepw '000|50[0-9]'
 t "failover: first server denies -> next" /failover_deny alice:alicepw 200
 local h; h=$(docker exec ngt curl -si -u alice:alicepw localhost/valid | tr -d '\r' | grep -i '^x-ldap\|^x-auth' | sort | tr '\n' ' ')
 if [[ "$h" == *"X-Auth-User: alice"* && "$h" == *"X-LDAP-givenName: Alice"* && "$h" == *"X-LDAP-mail: alice@example.org"* ]]; then PASS=$((PASS+1)); echo "  ok   headers: $h"; else FAILN=$((FAILN+1)); echo "  FAIL headers: $h"; fi
 local t0=$(date +%s.%N); local d; d=$(code -u alice:alicepw localhost/dead); local el=$(echo "$(date +%s.%N) - $t0" | bc)
 if [[ "$d" =~ ^(000|50[0-9])$ ]] && (( $(echo "$el < 9" | bc) )); then PASS=$((PASS+1)); echo "  ok   dead server ends in ${el}s (code $d)"; else FAILN=$((FAILN+1)); echo "  FAIL dead server code=$d time=$el"; fi
 # injection attempts in username (filter must be escaped)
 t "ldap injection uid=*" /valid '*:x' "$DENY"; t "ldap injection )(uid=*" /valid ')(uid=*:x' "$DENY"; t "ldap injection alice)(|(x=" /valid 'alice)(|(x=:alicepw' "$DENY"
}
for mode in st pool; do
  echo "=== MODE $mode, 1 worker"; start $mode 1; scen
  echo "  -- hung LDAP server (docker pause) then recovery"
  docker pause ldapsrv >/dev/null; t0=$(date +%s.%N); g=$(code -u alice:alicepw localhost/valid); el=$(echo "$(date +%s.%N) - $t0" | bc)
  if [[ "$g" != 200 ]] && (( $(echo "$el < 9" | bc) )); then PASS=$((PASS+1)); echo "  ok   hung server: code $g after ${el}s"; else FAILN=$((FAILN+1)); echo "  FAIL hung server code=$g time=$el"; fi
  docker unpause ldapsrv >/dev/null; sleep 1
  t "recovers after unpause (1)" /valid alice:alicepw 200; t "recovers after unpause (2)" /valid alice:alicepw 200; t "recovers: bad pw still denied" /valid alice:bad "$DENY"
  echo "  -- LDAP server down (stop) then up"
  docker stop ldapsrv >/dev/null; t "server stopped" /valid alice:alicepw '000|50[0-9]|401'; docker start ldapsrv >/dev/null
  for i in $(seq 40); do docker exec ldapsrv ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D cn=admin,dc=example,dc=org -w admin dn >/dev/null 2>&1 && break; sleep 2; done; sleep 12
  t "recovers after stop/start (1)" /valid alice:alicepw 200; t "recovers after stop/start (2)" /valid alice:alicepw 200
  echo "  crashes: $(docker logs ngt 2>&1 | grep -c 'exited on signal')"
done
echo "=== MODE st, 4 workers, 4000 parallel valid+bad"
start st 4
r=$(docker exec ngt sh -c "seq 4000 | xargs -P 80 -I{} sh -c 'pw=alicepw; [ \$(({}%4)) = 0 ] && pw=bad; curl -s -m 30 -o /dev/null -w \"%{http_code}\n\" -u alice:\$pw localhost/valid'" | sort | uniq -c | tr '\n' ' '); echo "  $r (want 3000x200, 1000x401)"
echo "  crashes: $(docker logs ngt 2>&1 | grep -c 'exited on signal')"
echo "=== MODE pool, 4 workers, 4000 parallel valid+bad"
start pool 4
r=$(docker exec ngt sh -c "seq 4000 | xargs -P 80 -I{} sh -c 'pw=alicepw; [ \$(({}%4)) = 0 ] && pw=bad; curl -s -m 30 -o /dev/null -w \"%{http_code}\n\" -u alice:\$pw localhost/valid'" | sort | uniq -c | tr '\n' ' '); echo "  $r (want 3000x200, 1000x401)"
echo "  crashes: $(docker logs ngt 2>&1 | grep -c 'exited on signal')"
echo "=== auth cache (stateless and pool): LDAP stopped, cached creds must still work, others must not"
for mode in st pool; do start $mode 1 cache
  t "[$mode] cache prime alice" /valid alice:alicepw 200; t "[$mode] cache prime bad pw" /valid alice:bad "$DENY"
  docker stop ldapsrv >/dev/null
  t "[$mode] cached alice, LDAP down" /valid alice:alicepw 200; t "[$mode] bad pw, LDAP down" /valid alice:bad '000|401|403|50[0-9]'; t "[$mode] uncached bob, LDAP down" /valid bob:bobpw '000|401|403|50[0-9]'
  docker start ldapsrv >/dev/null; for i in $(seq 40); do docker exec ldapsrv ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D cn=admin,dc=example,dc=org -w admin dn >/dev/null 2>&1 && break; sleep 2; done; sleep 12
  echo "  crashes: $(docker logs ngt 2>&1 | grep -c 'exited on signal')"
done
echo "TOTAL ok=$PASS fail=$FAILN"
[ "$FAILN" = 0 ]
