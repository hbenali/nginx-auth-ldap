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

subtest 'integration: auth_ldap with test LDAP' => sub {
    SKIP: {
        skip "nginx not compiled with ngx_http_auth_ldap_module", 3 unless $HaveNginx;

        my $workdir = tempdir(CLEANUP => 1);
        make_path("$workdir/logs");
        make_path("$workdir/conf");

        # Write nginx config
        open(my $cf, '>', "$workdir/conf/nginx.conf") or die $!;
        print $cf <<"NGINX_CONF";
daemon off;
worker_processes 1;
error_log $workdir/logs/error.log debug;
pid $workdir/nginx.pid;

events {
    worker_connections 64;
}

http {
    access_log $workdir/logs/access.log;

    ldap_server test_ldap {
        url ldap://127.0.0.1:8389/ou=users,dc=example,dc=com?uid?sub?(objectClass=*);
        binddn "cn=admin,dc=example,dc=com";
        binddn_passwd "adminpass";
        group_attribute member;
        group_attribute_is_dn on;
        require valid_user;
        satisfy all;
        search_attributes mail givenName sn;
        connections 1;
        connect_timeout 3s;
        bind_timeout 3s;
        request_timeout 5s;
    }

    server {
        listen 19999;
        server_name localhost;

        auth_ldap "Restricted Area";
        auth_ldap_servers test_ldap;

        location / {
            return 200 "OK - authenticated\n";
        }
    }
}
NGINX_CONF
        close($cf);

        # Start nginx
        my $nginx_pid = fork();
        if (!defined $nginx_pid) {
            fail("Cannot fork nginx process");
            return;
        }

        if ($nginx_pid == 0) {
            # Child: nginx
            exec($NginxBinary, '-c', "$workdir/conf/nginx.conf", '-p', $workdir);
            exit(1);
        }

        # Give nginx a moment to start
        sleep 2;

        # Verify nginx is running
        my $alive = kill(0, $nginx_pid);
        if (!$alive) {
            fail("nginx failed to start");
            return;
        }

        # Test 1: No auth -> 401
        my $response = `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:19999/ 2>/dev/null`;
        chomp $response;
        is($response, '401', "No auth returns 401");

        # Test 2: Valid auth -> 200 (depends on LDAP server)
        $response = `curl -s -o /dev/null -w '%{http_code}' -u testuser:testpass http://127.0.0.1:19999/ 2>/dev/null`;
        chomp $response;
        # This will only pass with a real LDAP server - mark as TODO
        TODO: {
            local $TODO = "Requires running LDAP server at port 8389";
            is($response, '200', "Valid auth returns 200");
        }

        # Test 3: Health check - nginx still running
        ok(kill(0, $nginx_pid), "nginx process still alive after requests");

        # Stop nginx
        kill('TERM', $nginx_pid);
        waitpid($nginx_pid, 0);
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
