#!/usr/bin/env bash
set -eu

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
test_dir=$(mktemp -d /tmp/crack-test.XXXXXX)
trap 'rm -f -- "$test_dir/crack"; rmdir -- "$test_dir"' EXIT

gcc -Wall -Wextra -Wpedantic -O2 -pthread "$script_dir/crack.c" \
    -lcrypt -o "$test_dir/crack"

passed=0
failed=0

run_test() {
    local name=$1 expected_status=$2 expected_output=$3
    shift 3
    local output status

    if output=$(timeout 10s "$test_dir/crack" "$@" 2>&1); then
        status=0
    else
        status=$?
    fi

    if [[ $status -eq $expected_status && "$output" == *"$expected_output"* ]]; then
        printf 'PASS: %s\n' "$name"
        passed=$((passed + 1))
    else
        printf 'FAIL: %s (exit %s; expected %s)\n' "$name" "$status" "$expected_status"
        if [[ $status -eq 124 ]]; then
            printf '  Timed out after 10 seconds.\n'
        else
            printf '  Expected output containing: %s\n  Actual: %s\n' "$expected_output" "$output"
        fi
        failed=$((failed + 1))
    fi
}

# Fixed DES hashes use salt "na" and the passwords apple and z.
run_test 'Single-thread apple example' 0 'Password cracked: apple' 1 5 na3C5487Wz4zw
run_test 'Four-thread alphabet boundary' 0 'Password cracked: z' 4 1 naq3ZU7R4isY.
run_test 'Missing arguments show usage' 1 'Usage:'

printf '\n%s passed, %s failed\n' "$passed" "$failed"
[[ $failed -eq 0 ]]
