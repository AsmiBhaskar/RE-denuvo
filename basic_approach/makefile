

CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = 

# OS detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LDFLAGS += -lpthread
endif
ifeq ($(UNAME_S),Darwin)
	LDFLAGS += -lpthread
endif

# Targets
TARGETS = protection_demo test_target test_target_protected

all: $(TARGETS)

# Basic protection framework
protection_demo: protection_framework.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Unprotected test target
test_target: test_target.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built unprotected target - try: strings test_target | grep Secret"

# Protected version (demonstrates some basic protections)
test_target_protected: test_target_protected.c
	$(CC) $(CFLAGS) -O2 -s -o $@ $< $(LDFLAGS)
	strip --strip-all $@ 2>/dev/null || strip $@ 2>/dev/null || true
	@echo "Built protected target with symbol stripping"

# Generate the protected version source (optional - will be created by script)
test_target_protected.c: test_target.c
	@echo "Run 'python3 generate_protected.py' to create protected version"

# Test the protection system
test: $(TARGETS)
	@echo "=== Testing Protection Framework ==="
	./protection_demo
	@echo ""
	@echo "=== Testing Unprotected Target ==="
	echo "skip" | ./test_target
	@echo ""
	@echo "=== Basic Analysis Commands ==="
	@echo "Try these commands to analyze the binaries:"
	@echo "  strings test_target | grep -i secret"
	@echo "  objdump -d test_target | grep -A10 validate_license"
	@echo "  nm test_target | grep -i secret"
	@echo "  hexdump -C test_target | grep -i secret"

# Clean build artifacts
clean:
	rm -f $(TARGETS) test_target_protected.c *.o

# Development targets
debug: CFLAGS += -g -DDEBUG
debug: $(TARGETS)

# Analysis helpers
analyze: test_target
	@echo "=== Static Analysis of Unprotected Binary ==="
	@echo "1. Searching for strings:"
	-strings test_target | grep -i "secret\|key\|license\|premium"
	@echo ""
	@echo "2. Exported symbols:"
	-nm test_target | grep -i "secret\|validate\|premium"
	@echo ""
	@echo "3. Disassembly of validate_license function:"
	-objdump -d test_target | grep -A20 "validate_license"
	@echo ""
	@echo "4. File information:"
	file test_target
	@echo ""
	@echo "5. Binary size and sections:"
	size test_target

# Create test scenarios
scenarios:
	@echo "=== Creating Test Scenarios ==="
	@echo "Scenario 1: Try to find the secret key"
	@echo "Command: strings test_target | grep ThisIsASecretKey"
	@echo ""
	@echo "Scenario 2: Try to patch the license check"
	@echo "Command: objdump -d test_target | grep -A10 validate_license"
	@echo ""
	@echo "Scenario 3: Try to modify the license_valid variable"
	@echo "Command: nm test_target | grep license_valid"

.PHONY: all test clean debug analyze scenarios