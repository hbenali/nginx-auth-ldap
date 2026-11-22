# Test image for test/integration: nginx with this module and a static, TLS-less libldap,
# plus curl. Build from the repository root:
#   docker build -f test/integration/Dockerfile -t ldaptest-nginx .
#   make test-docker IMG=ldaptest-nginx
FROM alpine:3.22 AS base
RUN apk add --no-cache build-base curl pcre2-dev zlib-dev openssl-dev linux-headers perl
WORKDIR /src
ARG NGINX_VERSION=1.28.0
ARG OPENLDAP_VERSION=2.6.10
RUN curl -fsSL https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz | tar xz \
 && curl -fsSL https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz | tar xz
RUN cd openldap-${OPENLDAP_VERSION} \
 && ./configure --prefix=/opt/ldap --disable-slapd --without-cyrus-sasl --without-tls \
      --enable-static --disable-shared --disable-backends --disable-overlays >/dev/null \
 && make depend >/dev/null && make -C include install >/dev/null \
 && make -j"$(nproc)" -C libraries >/dev/null && make -C libraries install >/dev/null

FROM base
ARG NGINX_VERSION=1.28.0
RUN adduser -D -H nginx
COPY config ngx_http_auth_ldap_module.c /src/mod/
RUN cd nginx-${NGINX_VERSION} && ./configure --prefix=/opt/nginx --sbin-path=/usr/sbin/nginx \
      --conf-path=/etc/nginx/nginx.conf --error-log-path=/dev/stderr --http-log-path=/dev/stdout \
      --with-http_ssl_module --with-cc-opt="-I/opt/ldap/include -Wall -Wextra -Wno-unused-parameter" \
      --with-ld-opt="-L/opt/ldap/lib" --add-module=/src/mod >/dev/null \
 && make -j"$(nproc)" >/dev/null && make install >/dev/null && mkdir -p /etc/nginx
ENTRYPOINT ["/usr/sbin/nginx"]
