#!/bin/bash

# Test script for SQL injection honeypot endpoints

BASE_URL="http://localhost:5000"

echo "========================================="
echo "Testing SQL Injection Honeypot Endpoints"
echo "========================================="
echo ""

# Test 1: Normal query
echo "Test 1: Normal GET request to /api/search"
curl -s "${BASE_URL}/api/search?q=test" | head -20
echo ""
echo "---"
echo ""

# Test 2: SQL injection with single quote
echo "Test 2: SQL injection with single quote"
curl -s "${BASE_URL}/api/search?id=1'" | head -20
echo ""
echo "---"
echo ""

# Test 3: UNION-based injection
echo "Test 3: UNION-based SQL injection"
curl -s "${BASE_URL}/api/search?id=1%20UNION%20SELECT%20*" | head -20
echo ""
echo "---"
echo ""

# Test 4: Boolean-based injection
echo "Test 4: Boolean-based SQL injection"
curl -s "${BASE_URL}/api/sql?user=admin'%20OR%201=1--" | head -20
echo ""
echo "---"
echo ""

# Test 5: Comment-based injection
echo "Test 5: Comment-based SQL injection"
curl -s "${BASE_URL}/api/database?q=test'--" | head -20
echo ""
echo "---"
echo ""

# Test 6: Time-based injection
echo "Test 6: Time-based SQL injection"
curl -s "${BASE_URL}/api/search?id=1%20AND%20SLEEP(5)" | head -20
echo ""
echo "---"
echo ""

# Test 7: POST request with SQL injection
echo "Test 7: POST request with SQL injection"
curl -s -X POST "${BASE_URL}/api/search" -d "username=admin'%20OR%201=1--&password=test" | head -20
echo ""
echo "---"
echo ""

# Test 8: Information schema query
echo "Test 8: Information schema injection"
curl -s "${BASE_URL}/api/sql?table=information_schema.tables" | head -20
echo ""
echo "---"
echo ""

# Test 9: Stacked queries
echo "Test 9: Stacked queries injection"
curl -s "${BASE_URL}/api/database?id=1;DROP%20TABLE%20users" | head -20
echo ""
echo "---"
echo ""

echo "========================================="
echo "Tests completed!"
echo "Check logs for detailed attack detection"
echo "========================================="
