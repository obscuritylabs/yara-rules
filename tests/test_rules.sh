#!/bin/bash

# Test script for YARA-X rules

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to test a rule
test_rule() {
    local rule_file=$1
    local test_file=$2
    local expected_result=$3

    echo "Testing rule: $(basename $rule_file)"
    echo "Against file: $(basename $test_file)"
    
    if yr "$rule_file" "$test_file" > /dev/null 2>&1; then
        if [ "$expected_result" = "match" ]; then
            echo -e "${GREEN}✓ Test passed: Expected match and got match${NC}"
        else
            echo -e "${RED}✗ Test failed: Expected no match but got match${NC}"
        fi
    else
        if [ "$expected_result" = "no_match" ]; then
            echo -e "${GREEN}✓ Test passed: Expected no match and got no match${NC}"
        else
            echo -e "${RED}✗ Test failed: Expected match but got no match${NC}"
        fi
    fi
    echo "----------------------------------------"
}

# Create test directory if it doesn't exist
mkdir -p tests/samples

# Test Go binary detection
echo "Testing Go binary detection..."
test_rule "../rules/compilers/Detect_Go_GOMAXPROCS.yara" "samples/go_binary" "match"
test_rule "../rules/compilers/Detect_Go_GOMAXPROCS.yara" "samples/non_go_binary" "no_match"

# Test NSIS installer detection
echo "Testing NSIS installer detection..."
test_rule "../rules/installers/Detect_NSIS_Installer.yara" "samples/nsis_installer" "match"
test_rule "../rules/installers/Detect_NSIS_Installer.yara" "samples/non_nsis_installer" "no_match"

echo "All tests completed!" 