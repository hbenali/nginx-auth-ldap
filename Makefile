CC = cc
CFLAGS = -Wall -Wextra -g -O0
LDFLAGS = -lldap -llber -lcrypto

UNIT_SRC = test/unit/test_utils.c
UNIT_BIN = test/unit/test_utils
UNIT_CACHE_SRC = test/unit/test_cache.c
UNIT_CACHE_BIN = test/unit/test_cache

NGINX_SRC_DIR ?= /usr/src/nginx
NGINX_VER ?= $(shell nginx -v 2>&1 | sed 's/.*\/\([0-9.]*\).*/\1/')
TEST_DIR = t

.PHONY: all test-unit test-integration test clean help check-leaks

all: test-unit

help:
	@echo "Targets:"
	@echo "  test-unit       Build and run unit tests"
	@echo "  test-integration Run integration tests (requires Test::Nginx)"
	@echo "  test            Run all tests (unit + integration)"
	@echo "  check-leaks     Run memory leak checks with valgrind"
	@echo "  clean           Clean build artifacts"

# --- Unit tests ---

$(UNIT_BIN): $(UNIT_SRC) test/unit/stubs.h
	$(CC) $(CFLAGS) -I. -DNGX_AUTH_LDAP_UNIT_TEST -o $@ $(UNIT_SRC)

$(UNIT_CACHE_BIN): $(UNIT_CACHE_SRC) test/unit/stubs.h
	$(CC) $(CFLAGS) -I. -DNGX_AUTH_LDAP_UNIT_TEST -o $@ $(UNIT_CACHE_SRC)

test-unit: $(UNIT_BIN) $(UNIT_CACHE_BIN)
	@echo "=== Running utility function tests ==="
	./$(UNIT_BIN)
	@echo "=== Running cache tests ==="
	./$(UNIT_CACHE_BIN)
	@echo "=== All unit tests passed ==="

# --- Integration tests ---

test-integration:
	@echo "=== Running nginx integration tests ==="
	@if command -v prove >/dev/null 2>&1; then \
		prove -v $(TEST_DIR)/*.t; \
	else \
		for t in $(TEST_DIR)/*.t; do perl $$t || exit 1; done; \
	fi

# --- Full test suite ---

test: test-unit test-integration

# --- Valgrind leak check ---

check-leaks: $(UNIT_BIN) $(UNIT_CACHE_BIN)
	valgrind --leak-check=full --show-leak-kinds=all ./$(UNIT_BIN)
	valgrind --leak-check=full --show-leak-kinds=all ./$(UNIT_CACHE_BIN)

# --- Cleanup ---

clean:
	rm -f $(UNIT_BIN) $(UNIT_CACHE_BIN)
	rm -f test/unit/*.o
