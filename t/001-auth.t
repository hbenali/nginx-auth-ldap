#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Cwd qw(abs_path);
use FindBin qw($Bin);

# Add lib path for MockLDAP
use lib "$Bin/lib";

# ============================================================================
# This test file requires:
#   1. nginx compiled with the ngx_http_auth_ldap_module
#   2. Test::Nginx Perl module
#   3. A running LDAP server or MockLDAP
#
# To run: prove -v t/001-auth.t
#
# If nginx with the module is not available, the test will SKIP.
# ============================================================================

my $NginxBinary = $ENV{TEST_NGINX_BINARY} || 'nginx';
my $HaveNginx = 0;

# Check if nginx is available with the module
my $modules = `$NginxBinary -V 2>&1`;
if ($modules =~ /ngx_http_auth_ldap_module/) {
    $HaveNginx = 1;
}

# ============================================================================
# Unit-like tests (no nginx required)
# ============================================================================

subtest 'unit: santitize_str function' => sub {
    my $c_output = `./test/unit/test_utils 2>/dev/null`;
    my $exit_code = $? >> 8;

    if ($exit_code == 0) {
        pass("sanitize_str tests passed");
    } elsif (! -f './test/unit/test_utils') {
        SKIP: {
            skip "test_utils binary not built (run 'make test-unit' first)", 1;
        }
    } else {
        diag("Output:\n$c_output");
        fail("sanitize_str tests failed (exit code: $exit_code)");
    }
};

subtest 'unit: cache functions' => sub {
    my $c_output = `./test/unit/test_cache 2>/dev/null`;
    my $exit_code = $? >> 8;

    if ($exit_code == 0) {
        pass("Cache tests passed");
    } elsif (! -f './test/unit/test_cache') {
        SKIP: {
            skip "test_cache binary not built (run 'make test-unit' first)", 1;
        }
    } else {
        diag("Output:\n$c_output");
        fail("Cache tests failed (exit code: $exit_code)");
    }
};

# ============================================================================
# Memory leak checks
# ============================================================================

subtest 'valgrind leak check: test_utils' => sub {
    SKIP: {
        skip "valgrind not available", 1 unless system("which valgrind >/dev/null 2>&1") == 0;
        skip "test_utils binary not built", 1 unless -f './test/unit/test_utils';

        my $output = `valgrind --leak-check=full --error-exitcode=99 ./test/unit/test_utils 2>&1`;
        my $exit = $? >> 8;

        if ($exit == 99) {
            diag("Valgrind output:\n$output");
            fail("Memory leak detected in test_utils");
        } elsif ($exit == 0) {
            pass("No memory leaks in test_utils");
        } else {
            skip "valgrind execution failed", 1;
        }
    }
};

subtest 'valgrind leak check: test_cache' => sub {
    SKIP: {
        skip "valgrind not available", 1 unless system("which valgrind >/dev/null 2>&1") == 0;
        skip "test_cache binary not built", 1 unless -f './test/unit/test_cache';

        my $output = `valgrind --leak-check=full --error-exitcode=99 ./test/unit/test_cache 2>&1`;
        my $exit = $? >> 8;

        if ($exit == 99) {
            diag("Valgrind output:\n$output");
            fail("Memory leak detected in test_cache");
        } elsif ($exit == 0) {
            pass("No memory leaks in test_cache");
        } else {
            skip "valgrind execution failed", 1;
        }
    }
};

# ============================================================================
# Integration tests (full nginx + LDAP, requires compiled module)
# ============================================================================

subtest 'integration: auth_ldap with a real LDAP server' => sub {
    # The old check here could not pass: "return 200" runs in the rewrite phase, before the
    # access phase where auth_ldap runs, and no LDAP server was started. The real thing is
    # test/integration/run.sh (make test-docker IMG=<image>): nginx against OpenLDAP.
    SKIP: {
        skip "run 'make test-docker IMG=<image with nginx + this module>' (needs Docker)", 1;
    }
};

# ============================================================================
# Configuration parsing tests (file-level checks)
# ============================================================================

subtest 'config: module directives exist in source' => sub {
    my $src_file = "$Bin/../ngx_http_auth_ldap_module.c";
    SKIP: {
        skip "Source file not found at $src_file", 6 unless -f $src_file;

        open(my $fh, '<', $src_file) or skip("Cannot open $src_file", 6);
        my $content = do { local $/; <$fh> };
        close($fh);

        like($content, qr/ldap_server/, "ldap_server directive defined");
        like($content, qr/auth_ldap_cache_enabled/, "auth_ldap_cache_enabled directive defined");
        like($content, qr/auth_ldap_cache_size/, "auth_ldap_cache_size directive defined");
        like($content, qr/stateless/, "stateless directive defined");
        like($content, qr/variable_basedn/, "variable_basedn directive defined");
        like($content, qr/SHM_CONFIG_VERSION_MAGIC/, "Shared memory infrastructure present");
    }
};

# ============================================================================
# Code quality checks
# ============================================================================

subtest 'code quality: critical patterns' => sub {
    my $src_file = "$Bin/../ngx_http_auth_ldap_module.c";
    SKIP: {
        skip "Source file not found at $src_file", 5 unless -f $src_file;

        open(my $fh, '<', $src_file) or skip("Cannot open $src_file", 5);
        my $content = do { local $/; <$fh> };
        close($fh);

        # Check for the bug fix: correct pointer cast
        like($content, qr/ngx_http_auth_ldap_server_t\s*\*\*\s*\)\s*conf->servers->elts/, 
            "Correct pointer-to-pointer cast in cache lookup");

        # Check for GNUC typo fix
        unlike($content, qr/^\s*#if\s+GNUC\s+>/m, 
            "No GNUC typo (uses __GNUC__)");

        # Check for X509_free in SSL handler
        like($content, qr/X509_free\(cert\)/, 
            "X509 cert properly freed in SSL handler");

        # Check for ldap_memfree in error path
        like($content, qr/ldap_memfree\(error_msg\).*close_connection/s, 
            "error_msg freed on ldap_parse_result failure path");

        # Check for deep-copy in cache update
        like($content, qr/cache_attr->attr_name\.data\s*=\s*ngx_pnalloc/, 
            "Cache attribute strings deep-copied to cache pool");
    }
};

done_testing();
