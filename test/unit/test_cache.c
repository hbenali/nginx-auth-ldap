#include "stubs.h"

/* Module constants needed for cache tests */
#define OUTCOME_ERROR          -1
#define OUTCOME_DENY            0
#define OUTCOME_ALLOW           1
#define OUTCOME_CACHED_DENY     2
#define OUTCOME_CACHED_ALLOW    3
#define OUTCOME_UNCERTAIN       4

#define DEFAULT_ATTRS_COUNT 3

/* Types from the main module */
typedef struct {
    ngx_str_t    attr_name;
    ngx_str_t    attr_value;
} ldap_search_attribute_t;

typedef struct {
    uint32_t     small_hash;
    uint32_t     outcome;
    ngx_msec_t   time;
    u_char       big_hash[16];
    ngx_array_t  attributes;
} ngx_http_auth_ldap_cache_elt_t;

typedef struct {
    ngx_http_auth_ldap_cache_elt_t *buckets;
    ngx_uint_t    num_buckets;
    ngx_uint_t    elts_per_bucket;
    ngx_msec_t    expiration_time;
    void         *pool;
} ngx_http_auth_ldap_cache_t;

/* Minimal server struct stub (only fields accessed by cache code) */
typedef struct {
    char _pad[1024]; /* enough to cover free_connections offset */
} ngx_http_auth_ldap_server_t;

/* Minimal request stub */
typedef struct {
    struct {
        ngx_str_t user;
        ngx_str_t passwd;
    } headers_in;
    void *pool;
} ngx_http_request_t;

/* Minimal context stub */
typedef struct {
    ngx_http_request_t *r;
    ngx_array_t         attributes;
    ngx_http_auth_ldap_cache_elt_t *cache_bucket;
    u_char              cache_big_hash[16];
    uint32_t            cache_small_hash;
} ngx_http_auth_ldap_ctx_t;

/* reimplement cache functions for testing */
static ngx_int_t
ngx_http_auth_ldap_check_cache(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
    ngx_http_auth_ldap_cache_t *cache, ngx_http_auth_ldap_server_t *server)
{
    ngx_http_auth_ldap_cache_elt_t *elt;
    ngx_md5_t md5ctx;
    ngx_msec_t time_limit;
    ngx_uint_t i;

    ctx->cache_small_hash = ngx_murmur_hash2(r->headers_in.user.data, r->headers_in.user.len) ^ (uint32_t) (ngx_uint_t) server;

    ngx_md5_init(&md5ctx);
    ngx_md5_update(&md5ctx, r->headers_in.user.data, r->headers_in.user.len);
    ngx_md5_update(&md5ctx, server, 1024); /* offsetof(server, free_connections) */
    ngx_md5_update(&md5ctx, r->headers_in.passwd.data, r->headers_in.passwd.len);
    ngx_md5_final(ctx->cache_big_hash, &md5ctx);

    ctx->cache_bucket = &cache->buckets[(ctx->cache_small_hash % cache->num_buckets) * cache->elts_per_bucket];

    elt = ctx->cache_bucket;
    time_limit = ngx_current_msec - cache->expiration_time;
    for (i = 0; i < cache->elts_per_bucket; i++, elt++) {
        if (elt->small_hash == ctx->cache_small_hash &&
                elt->time > time_limit &&
                memcmp(elt->big_hash, ctx->cache_big_hash, 16) == 0) {
            if (elt->outcome == OUTCOME_ALLOW || elt->outcome == OUTCOME_CACHED_ALLOW) {
                ctx->attributes.nelts = 0;
                {
                    ngx_uint_t k;
                    for (k = 0; k < elt->attributes.nelts; k++) {
                        ldap_search_attribute_t *src = (ldap_search_attribute_t *)elt->attributes.elts + k;
                        ldap_search_attribute_t *ctx_attr = ngx_array_push(&ctx->attributes);
                        if (ctx_attr == NULL) continue;
                        ctx_attr->attr_name.len = src->attr_name.len;
                        ctx_attr->attr_name.data = ngx_pnalloc(r->pool, src->attr_name.len + 1);
                        if (ctx_attr->attr_name.data != NULL) {
                            ngx_memcpy(ctx_attr->attr_name.data, src->attr_name.data, src->attr_name.len);
                            ctx_attr->attr_name.data[src->attr_name.len] = '\0';
                        }
                        ctx_attr->attr_value.len = src->attr_value.len;
                        ctx_attr->attr_value.data = ngx_pnalloc(r->pool, src->attr_value.len + 1);
                        if (ctx_attr->attr_value.data != NULL) {
                            ngx_memcpy(ctx_attr->attr_value.data, src->attr_value.data, src->attr_value.len);
                            ctx_attr->attr_value.data[src->attr_value.len] = '\0';
                        }
                    }
                }
            }
            return elt->outcome;
        }
    }

    return -1;
}

static void
ngx_http_auth_ldap_update_cache(ngx_http_auth_ldap_ctx_t *ctx,
        ngx_http_auth_ldap_cache_t *cache, ngx_flag_t outcome)
{
    ngx_http_auth_ldap_cache_elt_t *elt, *oldest_elt;
    ngx_uint_t i;

    elt = ctx->cache_bucket;
    oldest_elt = elt;
    for (i = 1; i < cache->elts_per_bucket; i++, elt++) {
        if (elt->time < oldest_elt->time) {
            oldest_elt = elt;
        }
    }

    oldest_elt->time = ngx_current_msec;
    oldest_elt->outcome = outcome;
    oldest_elt->small_hash = ctx->cache_small_hash;
    ngx_memcpy(oldest_elt->big_hash, ctx->cache_big_hash, 16);
    oldest_elt->attributes.nelts = 0;
    for (i = 0; i < ctx->attributes.nelts; i++) {
        ldap_search_attribute_t *src_attr = ((ldap_search_attribute_t *)ctx->attributes.elts + i);
        ldap_search_attribute_t *cache_attr = ngx_array_push(&oldest_elt->attributes);
        if (cache_attr == NULL) {
            break;
        }
        cache_attr->attr_name.len = src_attr->attr_name.len;
        cache_attr->attr_name.data = ngx_pnalloc(cache->pool, src_attr->attr_name.len + 1);
        if (cache_attr->attr_name.data != NULL) {
            ngx_memcpy(cache_attr->attr_name.data, src_attr->attr_name.data, src_attr->attr_name.len);
            cache_attr->attr_name.data[src_attr->attr_name.len] = '\0';
        }
        cache_attr->attr_value.len = src_attr->attr_value.len;
        cache_attr->attr_value.data = ngx_pnalloc(cache->pool, src_attr->attr_value.len + 1);
        if (cache_attr->attr_value.data != NULL) {
            ngx_memcpy(cache_attr->attr_value.data, src_attr->attr_value.data, src_attr->attr_value.len);
            cache_attr->attr_value.data[src_attr->attr_value.len] = '\0';
        }
    }
}


/* --- Test framework --- */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

static void test_start(const char *name) {
    tests_run++;
    printf("  TEST: %s ... ", name);
    fflush(stdout);
}

static void test_done(void) {
    printf("PASS\n");
    tests_passed++;
}

static void test_fail(const char *file, int line, const char *msg) {
    printf("FAIL\n    %s:%d: %s\n", file, line, msg);
    tests_failed++;
}

#define CHECK(cond) \
    do { if (!(cond)) { test_fail(__FILE__, __LINE__, "check failed: " #cond); return; } } while(0)

#define CHECK_EQ(a, b) \
    do { if ((a) != (b)) { char _buf[256]; snprintf(_buf, sizeof(_buf), "expected %zd, got %zd", (ssize_t)(b), (ssize_t)(a)); test_fail(__FILE__, __LINE__, _buf); return; } } while(0)


/* --- Cache test setup --- */

#define TEST_CACHE_BUCKETS 13
#define TEST_CACHE_ELTS    8

static ngx_http_auth_ldap_cache_t *create_cache(void) {
    ngx_http_auth_ldap_cache_t *cache = calloc(1, sizeof(*cache));
    cache->num_buckets = TEST_CACHE_BUCKETS;
    cache->elts_per_bucket = TEST_CACHE_ELTS;
    cache->expiration_time = 10000;
    cache->pool = cache; /* self-reference for alloc */

    cache->buckets = calloc(TEST_CACHE_BUCKETS * TEST_CACHE_ELTS, sizeof(ngx_http_auth_ldap_cache_elt_t));

    ngx_uint_t i;
    ngx_http_auth_ldap_cache_elt_t *entry = cache->buckets;
    for (i = 0; i < TEST_CACHE_BUCKETS * TEST_CACHE_ELTS; i++, entry++) {
        ngx_array_init(&entry->attributes, cache->pool, DEFAULT_ATTRS_COUNT, sizeof(ldap_search_attribute_t));
    }

    return cache;
}

static void destroy_cache(ngx_http_auth_ldap_cache_t *cache) {
    if (cache == NULL) return;
    ngx_uint_t i;
    ngx_http_auth_ldap_cache_elt_t *entry = cache->buckets;
    for (i = 0; i < TEST_CACHE_BUCKETS * TEST_CACHE_ELTS; i++, entry++) {
        ngx_uint_t k;
        ldap_search_attribute_t *attr = (ldap_search_attribute_t *)entry->attributes.elts;
        for (k = 0; k < entry->attributes.nelts; k++, attr++) {
            free(attr->attr_name.data);
            free(attr->attr_value.data);
        }
        free(entry->attributes.elts);
    }
    free(cache->buckets);
    free(cache);
}

static void setup_ctx(ngx_http_auth_ldap_ctx_t *ctx, const char *user, const char *pass) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->r = calloc(1, sizeof(ngx_http_request_t));
    ctx->r->headers_in.user.data = (u_char *)user;
    ctx->r->headers_in.user.len = strlen(user);
    ctx->r->headers_in.passwd.data = (u_char *)pass;
    ctx->r->headers_in.passwd.len = strlen(pass);
    ctx->r->pool = ctx->r; /* self-ref for alloc */
    ngx_array_init(&ctx->attributes, ctx->r->pool, DEFAULT_ATTRS_COUNT, sizeof(ldap_search_attribute_t));
}

static void teardown_ctx(ngx_http_auth_ldap_ctx_t *ctx) {
    ngx_uint_t k;
    ldap_search_attribute_t *attr = (ldap_search_attribute_t *)ctx->attributes.elts;
    for (k = 0; k < ctx->attributes.nelts; k++, attr++) {
        free(attr->attr_name.data);
        free(attr->attr_value.data);
    }
    free(ctx->attributes.elts);
    free(ctx->r);
    memset(ctx, 0, sizeof(*ctx));
}

/* --- Cache tests --- */

static void test_cache_miss_empty(void) {
    test_start("cache miss on empty cache");
    ngx_http_auth_ldap_cache_t *cache = create_cache();
    ngx_http_auth_ldap_ctx_t ctx;
    ngx_http_auth_ldap_server_t server;

    setup_ctx(&ctx, "testuser", "testpass");
    ngx_int_t rc = ngx_http_auth_ldap_check_cache(ctx.r, &ctx, cache, &server);
    CHECK_EQ(rc, -1);
    CHECK(ctx.cache_small_hash != 0);

    teardown_ctx(&ctx);
    destroy_cache(cache);
    test_done();
}

static void test_cache_store_and_hit(void) {
    test_start("cache store and hit");
    ngx_http_auth_ldap_cache_t *cache = create_cache();
    ngx_http_auth_ldap_ctx_t ctx;
    ngx_http_auth_ldap_server_t server1;

    /* First, do a check to set up the cache_bucket and hashes */
    setup_ctx(&ctx, "bob", "secret123");
    ngx_http_auth_ldap_check_cache(ctx.r, &ctx, cache, &server1);

    /* Store an ALLOW outcome */
    ngx_http_auth_ldap_update_cache(&ctx, cache, OUTCOME_ALLOW);

    /* Check again - should hit */
    setup_ctx(&ctx, "bob", "secret123");
    ngx_int_t rc = ngx_http_auth_ldap_check_cache(ctx.r, &ctx, cache, &server1);
    CHECK_EQ(rc, OUTCOME_ALLOW);

    teardown_ctx(&ctx);
    destroy_cache(cache);
    test_done();
}

static void test_cache_store_deny_and_hit(void) {
    test_start("cache store DENY and hit");
    ngx_http_auth_ldap_cache_t *cache = create_cache();
    ngx_http_auth_ldap_ctx_t ctx;
    ngx_http_auth_ldap_server_t server;

    setup_ctx(&ctx, "alice", "wrong");
    ngx_http_auth_ldap_check_cache(ctx.r, &ctx, cache, &server);
    ngx_http_auth_ldap_update_cache(&ctx, cache, OUTCOME_DENY);

    setup_ctx(&ctx, "alice", "wrong");
    ngx_int_t rc = ngx_http_auth_ldap_check_cache(ctx.r, &ctx, cache, &server);
    CHECK_EQ(rc, OUTCOME_DENY);

    teardown_ctx(&ctx);
    destroy_cache(cache);
    test_done();
}

static void test_cache_different_passwords(void) {
    test_start("cache different passwords -> miss");
    ngx_http_auth_ldap_cache_t *cache = create_cache();
    ngx_http_auth_ldap_ctx_t ctx;
    ngx_http_auth_ldap_server_t server;

    setup_ctx(&ctx, "eve", "password1");
    ngx_http_auth_ldap_check_cache(ctx.r, &ctx, cache, &server);
    ngx_http_auth_ldap_update_cache(&ctx, cache, OUTCOME_ALLOW);

    setup_ctx(&ctx, "eve", "password2");
    ngx_int_t rc = ngx_http_auth_ldap_check_cache(ctx.r, &ctx, cache, &server);
    CHECK_EQ(rc, -1);

    teardown_ctx(&ctx);
    destroy_cache(cache);
    test_done();
}

static void test_cache_bucket_eviction(void) {
    test_start("cache bucket LRU eviction");
    ngx_http_auth_ldap_cache_t *cache = create_cache();
    ngx_http_auth_ldap_ctx_t ctx;
    ngx_uint_t i;

    char user[32];
    char pass[32];

    for (i = 0; i < 8; i++) {
        snprintf(user, sizeof(user), "bucketuser%lu", (unsigned long)i);
        snprintf(pass, sizeof(pass), "pass%lu", (unsigned long)i);
        setup_ctx(&ctx, user, pass);
        ctx.cache_small_hash = 0;
        ctx.cache_bucket = cache->buckets;
        ngx_current_msec += 100;
        ngx_http_auth_ldap_update_cache(&ctx, cache, OUTCOME_ALLOW);
        teardown_ctx(&ctx);
    }

    setup_ctx(&ctx, "bucketuser9", "pass9");
    ctx.cache_small_hash = 0;
    ctx.cache_bucket = cache->buckets;
    ngx_current_msec += 100;
    ngx_http_auth_ldap_update_cache(&ctx, cache, OUTCOME_ALLOW);
    teardown_ctx(&ctx);

    ngx_http_auth_ldap_cache_elt_t *elt = cache->buckets;
    int found = 0;
    for (i = 0; i < cache->elts_per_bucket; i++, elt++) {
        if (elt->outcome == OUTCOME_ALLOW && elt->small_hash == 0) {
            found++;
        }
    }
    CHECK(found >= 7);

    destroy_cache(cache);
    test_done();
}

static void test_cache_expiration(void) {
    test_start("cache expiration");
    ngx_http_auth_ldap_cache_t *cache = create_cache();
    cache->expiration_time = 100;

    ngx_http_auth_ldap_ctx_t ctx;
    ngx_http_auth_ldap_server_t server;

    setup_ctx(&ctx, "timeduser", "timedpass");
    ngx_http_auth_ldap_check_cache(ctx.r, &ctx, cache, &server);
    ngx_http_auth_ldap_update_cache(&ctx, cache, OUTCOME_ALLOW);
    teardown_ctx(&ctx);

    /* Advance time beyond expiration */
    ngx_current_msec += 200;

    setup_ctx(&ctx, "timeduser", "timedpass");
    ngx_int_t rc = ngx_http_auth_ldap_check_cache(ctx.r, &ctx, cache, &server);
    CHECK_EQ(rc, -1);

    teardown_ctx(&ctx);
    cache->expiration_time = 10000;
    destroy_cache(cache);
    test_done();
}

static void test_cache_with_attributes(void) {
    test_start("cache store and retrieve with attributes");
    ngx_http_auth_ldap_cache_t *cache = create_cache();
    ngx_http_auth_ldap_ctx_t ctx;
    ngx_http_auth_ldap_server_t server;

    setup_ctx(&ctx, "attruser", "attrpass");

    /* Add a test attribute to context */
    ldap_search_attribute_t *attr = ngx_array_push(&ctx.attributes);
    attr->attr_name.data = ngx_pnalloc(ctx.r->pool, 5);
    memcpy(attr->attr_name.data, "mail", 4);
    attr->attr_name.data[4] = '\0';
    attr->attr_name.len = 4;

    attr->attr_value.data = ngx_pnalloc(ctx.r->pool, 16);
    memcpy(attr->attr_value.data, "user@example.com", 16);
    attr->attr_value.len = 16;

    ngx_http_auth_ldap_check_cache(ctx.r, &ctx, cache, &server);
    ngx_http_auth_ldap_update_cache(&ctx, cache, OUTCOME_ALLOW);
    teardown_ctx(&ctx);

    /* Verify we can retrieve it */
    setup_ctx(&ctx, "attruser", "attrpass");
    ngx_int_t rc = ngx_http_auth_ldap_check_cache(ctx.r, &ctx, cache, &server);
    CHECK_EQ(rc, OUTCOME_ALLOW);
    CHECK(ctx.attributes.nelts >= 1);

    ldap_search_attribute_t *ret = (ldap_search_attribute_t *)ctx.attributes.elts;
    CHECK(ret->attr_name.len == 4);
    CHECK(ret->attr_value.len == 16);
    CHECK(memcmp(ret->attr_name.data, "mail", 4) == 0);

    teardown_ctx(&ctx);
    destroy_cache(cache);
    test_done();
}


/* --- Main --- */

int main(void) {
    printf("\n=== nginx-auth-ldap: Cache Unit Tests ===\n\n");

    test_cache_miss_empty();
    test_cache_store_and_hit();
    test_cache_store_deny_and_hit();
    test_cache_different_passwords();
    test_cache_bucket_eviction();
    test_cache_expiration();
    test_cache_with_attributes();

    printf("\n=== Results: %d run, %d passed, %d failed ===\n",
        tests_run, tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
