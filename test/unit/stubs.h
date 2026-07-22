#ifndef NGX_AUTH_LDAP_TEST_STUBS_H
#define NGX_AUTH_LDAP_TEST_STUBS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/* Minimal nginx type stubs for standalone test compilation */

typedef intptr_t ngx_int_t;
typedef uintptr_t ngx_uint_t;
typedef int ngx_flag_t;

#define NGX_OK      0
#define NGX_ERROR  -1
#define NGX_AGAIN  -2
#define NGX_DECLINED -3
#define NGX_BUSY   -4
#define NGX_CONF_ERROR -5

#define NGX_UNSET_PTR ((void *) -1)
#define NGX_CONF_UNSET -1
#define NGX_CONF_UNSET_PTR ((void *) -1)
#define NGX_CONF_UNSET_SIZE ((size_t) -1)
#define NGX_CONF_UNSET_MSEC ((ngx_msec_t) -1)

#define NGX_LOG_EMERG   0
#define NGX_LOG_ALERT   1
#define NGX_LOG_CRIT    2
#define NGX_LOG_ERR     3
#define NGX_LOG_WARN    4
#define NGX_LOG_NOTICE  5
#define NGX_LOG_INFO    6
#define NGX_LOG_DEBUG   7

#define NGX_DEBUG_LOG_HTTP 0x1000

#define NGX_HTTP_MAIN_CONF   0x02000000
#define NGX_HTTP_SRV_CONF    0x04000000
#define NGX_HTTP_LOC_CONF    0x08000000
#define NGX_HTTP_LMT_CONF    0x10000000
#define NGX_CONF_BLOCK       0x00000100
#define NGX_CONF_TAKE1       0x00000001
#define NGX_CONF_ANY         0x0000000F
#define NGX_CONF_1MORE       0x00000008
#define NGX_CONF_FLAG        0x00000002

#define NGX_HTTP_MAIN_CONF_OFFSET  0
#define NGX_HTTP_LOC_CONF_OFFSET   sizeof(void *)

typedef intptr_t ngx_msec_t;
typedef intptr_t ngx_socket_t;
typedef intptr_t ngx_fd_t;
__attribute__((unused))
static ngx_msec_t ngx_current_msec = 1000000;
typedef intptr_t ngx_fd_t;
typedef struct ngx_str_t {
    size_t   len;
    u_char  *data;
} ngx_str_t;

#define ngx_string(str)  { sizeof(str) - 1, (u_char *) str }
#define ngx_str_set(str, text)  (str)->len = sizeof(text) - 1; (str)->data = (u_char *) (text)
#define ngx_strlen(s)  strlen((const char *)(s))
#define ngx_strcmp(s1, s2)  strcmp((const char *)(s1), (const char *)(s2))
#define ngx_strcasecmp(s1, s2)  strcasecmp((const char *)(s1), (const char *)(s2))
#define ngx_strchr(s, c)  strchr((const char *)(s), (int)(c))
#define ngx_memcmp(s1, s2, n)  memcmp(s1, s2, n)
#define ngx_memcpy(d, s, n)  memcpy(d, s, n)
#define ngx_memzero(p, n)  memset(p, 0, n)
#define ngx_cpymem(d, s, n)  (((u_char *)memcpy(d, s, n)) + (n))
#define ngx_memmove(d, s, n)  memmove(d, s, n)
#define ngx_sprintf  sprintf
#define ngx_snprintf  snprintf

static inline void *ngx_palloc(void *pool, size_t size) {
    (void)pool;
    return malloc(size);
}
static inline void *ngx_pcalloc(void *pool, size_t size) {
    (void)pool;
    return calloc(1, size);
}
static inline void *ngx_pnalloc(void *pool, size_t size) {
    (void)pool;
    return malloc(size);
}
static inline void ngx_pfree(void *pool, void *p) {
    (void)pool;
    free(p);
}

#define ngx_alloc(size, log)  malloc(size)
#define ngx_calloc(size, log) calloc(1, size)

#define offsetof(T, member) __builtin_offsetof(T, member)

#define ngx_log_debug0(level, log, err, fmt)  /* noop */
#define ngx_log_debug1(level, log, err, fmt, a1)  /* noop */
#define ngx_log_debug2(level, log, err, fmt, a1, a2)  /* noop */
#define ngx_log_debug3(level, log, err, fmt, a1, a2, a3)  /* noop */
#define ngx_log_debug4(level, log, err, fmt, a1, a2, a3, a4)  /* noop */
#define ngx_log_error(level, log, err, fmt, ...)  fprintf(stderr, fmt "\n", ##__VA_ARGS__)

#define ngx_random()  rand()

typedef struct {
    u_char *data;
    size_t  len;
} ngx_buf_t;

#define LDAP_NO_ATTRS "1.1"

/* MurmurHash2 stub for cache tests */
__attribute__((unused))
static uint32_t ngx_murmur_hash2(u_char *data, size_t len) {
    uint32_t h = 0x9747b28c;
    uint32_t k;
    size_t i;

    for (i = 0; i + 4 <= len; i += 4) {
        k = ((uint32_t)data[i]) | ((uint32_t)data[i+1] << 8) |
            ((uint32_t)data[i+2] << 16) | ((uint32_t)data[i+3] << 24);
        k *= 0x5bd1e995;
        k ^= k >> 24;
        k *= 0x5bd1e995;
        h *= 0x5bd1e995;
        h ^= k;
    }

    switch (len - i) {
    case 3: h ^= (uint32_t)data[i+2] << 16; /* fallthrough */
    case 2: h ^= (uint32_t)data[i+1] << 8;  /* fallthrough */
    case 1: h ^= (uint32_t)data[i];
            h *= 0x5bd1e995;
    }

    h ^= h >> 13;
    h *= 0x5bd1e995;
    h ^= h >> 15;
    return h;
}

/* Minimal MD5 context stub */
typedef struct {
    uint64_t bytes;
    uint32_t a, b, c, d;
    u_char buffer[64];
} ngx_md5_t;

#define ngx_md5_init(ctx)  ngx_md5_stub_init(ctx)
#define ngx_md5_update(ctx, data, len)  ngx_md5_stub_update(ctx, data, len)
#define ngx_md5_final(result, ctx)  ngx_md5_stub_final(result, ctx)

/* Minimal ngx_array_t */
typedef struct {
    void        *elts;
    ngx_uint_t   nelts;
    size_t       size;
    ngx_uint_t   nalloc;
    void        *pool;
} ngx_array_t;

static inline ngx_int_t ngx_array_init(ngx_array_t *array, void *pool, ngx_uint_t n, size_t size) {
    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;
    array->elts = calloc(n, size);
    return (array->elts == NULL) ? NGX_ERROR : NGX_OK;
}

static inline void *ngx_array_push(ngx_array_t *a) {
    if (a->nelts == a->nalloc) {
        ngx_uint_t n = a->nalloc * 2;
        void *new_elts = realloc(a->elts, n * a->size);
        if (new_elts == NULL) return NULL;
        memset((u_char *)new_elts + a->nelts * a->size, 0, (n - a->nelts) * a->size);
        a->elts = new_elts;
        a->nalloc = n;
    }
    void *p = (u_char *)a->elts + a->nelts * a->size;
    a->nelts++;
    return p;
}

/* MD5 stub - simplified for testing (not cryptographically correct) */
__attribute__((unused))
static void ngx_md5_stub_init(ngx_md5_t *ctx) {
    ctx->bytes = 0;
    ctx->a = 0x67452301;
    ctx->b = 0xefcdab89;
    ctx->c = 0x98badcfe;
    ctx->d = 0x10325476;
}

__attribute__((unused))
static void ngx_md5_stub_update(ngx_md5_t *ctx, const void *data, size_t len) {
    /* Simplified: just hash bytes into a simple checksum for testing */
    const u_char *p = data;
    for (size_t i = 0; i < len; i++) {
        ctx->bytes++;
        ctx->a = ctx->a ^ (ctx->a << 5) ^ p[i];
        ctx->b = ctx->b ^ (ctx->b << 7) ^ p[i];
        ctx->c = ctx->c ^ (ctx->c << 11) ^ p[i];
        ctx->d = ctx->d ^ (ctx->d << 13) ^ p[i];
    }
}

__attribute__((unused))
static void ngx_md5_stub_final(u_char result[16], ngx_md5_t *ctx) {
    /* Simplified: just output accumulated state */
    memcpy(result, &ctx->a, 4);
    memcpy(result + 4, &ctx->b, 4);
    memcpy(result + 8, &ctx->c, 4);
    memcpy(result + 12, &ctx->d, 4);
}

#endif /* NGX_AUTH_LDAP_TEST_STUBS_H */
