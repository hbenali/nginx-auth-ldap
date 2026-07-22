#include "stubs.h"

/* Include utility function implementations from the main module source.
 * We use preprocessor tricks to extract just the utility functions. */

/* Constants from the main module */
#define SANITIZE_NO_CONV  0
#define SANITIZE_TO_UPPER 1
#define SANITIZE_TO_LOWER 2
#define DEFAULT_ATTRS_COUNT 3

/* Re-implement the utility functions inline for testing */
static u_char * santitize_str(u_char *str, ngx_uint_t conv) {
    static u_char sanitizeTable[256] = {0xff};
    ngx_uint_t i;
    u_char *p;

    if (str == NULL || *str == '\0') {
        return str;
    }

    if (sanitizeTable[0] == 0xff) {
        for (i = 0; i < sizeof(sanitizeTable); i++) {
            sanitizeTable[i] = (isalnum(i) || i == '-' || i == '_') ? i : '_';
        }
    }

    for (p = str; *p; p++) {
        if (conv == SANITIZE_TO_UPPER && *p >= 97 && *p <= 122) {
            *p -= 32;
        } else if (conv == SANITIZE_TO_LOWER && *p >= 65 && *p <= 90) {
            *p += 32;
        } else {
            *p = sanitizeTable[(int)*p];
        }
    }
    return str;
}

static ngx_uint_t
my_hex_digit_value(u_char c)
{
    if (c >= '0' && c <= '9') {
        return (ngx_uint_t)(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return (ngx_uint_t)(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return (ngx_uint_t)(c - 'A' + 10);
    }
    return 0;
}

static ngx_uint_t
my_hex_decode(ngx_str_t *dst, ngx_str_t *src)
{
    u_char     *s, *d;
    ngx_uint_t i;

    if (src->len < 2) {
        dst->len = 0;
        return 0;
    }

    for (i = 0, s = src->data, d = dst->data ; i < src->len -1; i += 2, s += 2) {
        *d++ = (u_char)(16 * my_hex_digit_value(*s) + my_hex_digit_value(*(s + 1)));
    }

    dst->len = (d - dst->data);
    return (ngx_uint_t)dst->len;
}


/* --- Test framework --- */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static const char *current_test = NULL;

static void test_start(const char *name) {
    tests_run++;
    current_test = name;
    printf("  TEST: %s ... ", name);
    fflush(stdout);
}

static void test_done(void) {
    printf("PASS\n");
    tests_passed++;
    current_test = NULL;
}

static void test_fail(const char *file, int line, const char *msg) {
    printf("FAIL\n    %s:%d: %s\n", file, line, msg);
    tests_failed++;
    current_test = NULL;
}

#define CHECK(cond) \
    do { if (!(cond)) { test_fail(__FILE__, __LINE__, "check failed: " #cond); return; } } while(0)

#define CHECK_EQ(a, b) \
    do { if ((a) != (b)) { char _buf[256]; snprintf(_buf, sizeof(_buf), "expected %zd, got %zd", (ssize_t)(b), (ssize_t)(a)); test_fail(__FILE__, __LINE__, _buf); return; } } while(0)

#define CHECK_STREQ(a, b, len) \
    do { if ((len) != (int)strlen(b) || memcmp((a), (b), (len)) != 0) { char _buf[256]; snprintf(_buf, sizeof(_buf), "expected '%.*s', got '%.*s'", (int)strlen(b), (b), (int)(len), (char*)(a)); test_fail(__FILE__, __LINE__, _buf); return; } } while(0)

#define CHECK_NULL(p) \
    do { if ((p) != NULL) { test_fail(__FILE__, __LINE__, "expected NULL"); return; } } while(0)


/* --- sanitize_str tests --- */

static void test_sanitize_empty(void) {
    test_start("sanitize_str empty string");
    u_char s[] = "";
    u_char *r = santitize_str(s, SANITIZE_NO_CONV);
    CHECK_EQ(r[0], '\0');
    test_done();
}

static void test_sanitize_null(void) {
    test_start("sanitize_str NULL returns NULL");
    u_char *r = santitize_str(NULL, SANITIZE_NO_CONV);
    CHECK_NULL(r);
    test_done();
}

static void test_sanitize_alphanumeric(void) {
    test_start("sanitize_str alphanumeric unchanged");
    u_char s[] = "abcXYZ123";
    santitize_str(s, SANITIZE_NO_CONV);
    CHECK_STREQ(s, "abcXYZ123", 9);
    test_done();
}

static void test_sanitize_special_chars(void) {
    test_start("sanitize_str replaces special chars with underscore");
    u_char s[] = "hello world!@#$";
    santitize_str(s, SANITIZE_NO_CONV);
    CHECK_STREQ(s, "hello_world____", 15);
    test_done();
}

static void test_sanitize_keep_dash_underscore(void) {
    test_start("sanitize_str keeps dash and underscore");
    u_char s[] = "test-name_value";
    santitize_str(s, SANITIZE_NO_CONV);
    CHECK_STREQ(s, "test-name_value", 15);
    test_done();
}

static void test_sanitize_to_upper(void) {
    test_start("sanitize_str SANITIZE_TO_UPPER");
    u_char s[] = "hello world";
    santitize_str(s, SANITIZE_TO_UPPER);
    CHECK_STREQ(s, "HELLO_WORLD", 11);
    test_done();
}

static void test_sanitize_to_lower(void) {
    test_start("sanitize_str SANITIZE_TO_LOWER");
    u_char s[] = "HELLO WORLD!";
    santitize_str(s, SANITIZE_TO_LOWER);
    CHECK_STREQ(s, "hello_world_", 12);
    test_done();
}

static void test_sanitize_mixed_chars(void) {
    test_start("sanitize_str mixed input");
    u_char s[] = "X-LDAP-ATTR-mail@domain";
    santitize_str(s, SANITIZE_NO_CONV);
    CHECK_STREQ(s, "X-LDAP-ATTR-mail_domain", 23);
    test_done();
}

/* --- hex_digit_value tests --- */

static void test_hex_digit_0_9(void) {
    test_start("hex_digit_value for 0-9");
    CHECK_EQ(my_hex_digit_value('0'), 0);
    CHECK_EQ(my_hex_digit_value('5'), 5);
    CHECK_EQ(my_hex_digit_value('9'), 9);
    test_done();
}

static void test_hex_digit_a_f(void) {
    test_start("hex_digit_value for a-f/A-F");
    CHECK_EQ(my_hex_digit_value('a'), 10);
    CHECK_EQ(my_hex_digit_value('f'), 15);
    CHECK_EQ(my_hex_digit_value('A'), 10);
    CHECK_EQ(my_hex_digit_value('F'), 15);
    test_done();
}

static void test_hex_digit_invalid(void) {
    test_start("hex_digit_value for invalid chars returns 0");
    CHECK_EQ(my_hex_digit_value('g'), 0);
    CHECK_EQ(my_hex_digit_value('z'), 0);
    CHECK_EQ(my_hex_digit_value('!'), 0);
    CHECK_EQ(my_hex_digit_value(0), 0);
    test_done();
}

/* --- hex_decode tests --- */

static void test_hex_decode_simple(void) {
    test_start("hex_decode simple");
    u_char src[] = "48656c6c6f"; /* "Hello" in hex */
    u_char dst[10] = {0};
    ngx_str_t s = {10, src};
    ngx_str_t d = {sizeof(dst), dst};
    ngx_uint_t n = my_hex_decode(&d, &s);
    CHECK_EQ(n, 5);
    CHECK_STREQ(dst, "Hello", 5);
    test_done();
}

static void test_hex_decode_password(void) {
    test_start("hex_decode bind password");
    u_char src[] = "736563726574"; /* "secret" */
    u_char dst[10] = {0};
    ngx_str_t s = {12, src};
    ngx_str_t d = {sizeof(dst), dst};
    my_hex_decode(&d, &s);
    CHECK_STREQ(dst, "secret", 6);
    test_done();
}

static void test_hex_decode_uppercase(void) {
    test_start("hex_decode uppercase input");
    u_char src[] = "414243"; /* "ABC" */
    u_char dst[10] = {0};
    ngx_str_t s = {6, src};
    ngx_str_t d = {sizeof(dst), dst};
    my_hex_decode(&d, &s);
    CHECK_STREQ(dst, "ABC", 3);
    test_done();
}

static void test_hex_decode_empty(void) {
    test_start("hex_decode empty input");
    u_char src[] = "";
    u_char dst[10] = {0};
    ngx_str_t s = {0, src};
    ngx_str_t d = {sizeof(dst), dst};
    ngx_uint_t n = my_hex_decode(&d, &s);
    CHECK_EQ(n, 0);
    test_done();
}

/* --- ngx_array_init / ngx_array_push tests (used by cache) --- */

static void test_array_init_and_push(void) {
    test_start("array_init and array_push");
    ngx_array_t arr;
    ngx_uint_t rc = ngx_array_init(&arr, NULL, 4, sizeof(ngx_uint_t));
    CHECK_EQ(rc, NGX_OK);
    CHECK_EQ(arr.nelts, 0);
    CHECK_EQ(arr.nalloc, 4);

    ngx_uint_t *v;
    v = ngx_array_push(&arr);
    CHECK(v != NULL);
    *v = 42;
    CHECK_EQ(arr.nelts, 1);

    v = ngx_array_push(&arr);
    CHECK(v != NULL);
    *v = 99;
    CHECK_EQ(arr.nelts, 2);
    CHECK_EQ(*(ngx_uint_t *)arr.elts, 42);
    CHECK_EQ(*((ngx_uint_t *)arr.elts + 1), 99);

    free(arr.elts);
    test_done();
}

static void test_array_push_grow(void) {
    test_start("array_push grows array when full");
    ngx_array_t arr;
    ngx_array_init(&arr, NULL, 2, sizeof(ngx_uint_t));

    ngx_uint_t *v;
    v = ngx_array_push(&arr); *v = 1;
    v = ngx_array_push(&arr); *v = 2;
    CHECK_EQ(arr.nelts, 2);
    CHECK_EQ(arr.nalloc, 2);

    v = ngx_array_push(&arr); *v = 3;
    CHECK_EQ(arr.nelts, 3);
    CHECK(v != NULL);
    CHECK(arr.nalloc >= 3);

    free(arr.elts);
    test_done();
}


/* --- Main --- */

int main(void) {
    printf("\n=== nginx-auth-ldap: Utility Function Unit Tests ===\n\n");

    test_sanitize_empty();
    test_sanitize_null();
    test_sanitize_alphanumeric();
    test_sanitize_special_chars();
    test_sanitize_keep_dash_underscore();
    test_sanitize_to_upper();
    test_sanitize_to_lower();
    test_sanitize_mixed_chars();

    test_hex_digit_0_9();
    test_hex_digit_a_f();
    test_hex_digit_invalid();

    test_hex_decode_simple();
    test_hex_decode_password();
    test_hex_decode_uppercase();
    test_hex_decode_empty();

    test_array_init_and_push();
    test_array_push_grow();

    printf("\n=== Results: %d run, %d passed, %d failed ===\n",
        tests_run, tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
