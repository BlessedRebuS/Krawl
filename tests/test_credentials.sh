#!/bin/bash

# This script sends various POST requests with credentials to the honeypot

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
HOST="localhost"
PORT="5000"
BASE_URL="http://${HOST}:${PORT}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Krawl Credential Logging Test Script${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Check if server is running
echo -e "${YELLOW}Checking if server is running on ${BASE_URL}...${NC}"
if ! curl -s -f "${BASE_URL}/health" > /dev/null 2>&1; then
    echo -e "${RED}❌ Server is not running. Please start the Krawl server first.${NC}"
    echo -e "${YELLOW}Run: python3 src/server.py${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Server is running${NC}\n"

# Test 1: Simple login form POST
echo -e "${YELLOW}Test 1: POST to /login with form data${NC}"
curl -s -X POST "${BASE_URL}/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=admin123" \
    > /dev/null
echo -e "${GREEN}✓ Sent: admin / admin123${NC}\n"

sleep 1

# Test 2: Admin panel login
echo -e "${YELLOW}Test 2: POST to /admin with credentials${NC}"
curl -s -X POST "${BASE_URL}/admin" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "user=root&pass=toor&submit=Login" \
    > /dev/null
echo -e "${GREEN}✓ Sent: root / toor${NC}\n"

sleep 1

# Test 3: WordPress login attempt
echo -e "${YELLOW}Test 3: POST to /wp-login.php${NC}"
curl -s -X POST "${BASE_URL}/wp-login.php" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "log=wpuser&pwd=Password1&wp-submit=Log+In" \
    > /dev/null
echo -e "${GREEN}✓ Sent: wpuser / Password1${NC}\n"

sleep 1

# Test 4: JSON formatted credentials
echo -e "${YELLOW}Test 4: POST to /api/login with JSON${NC}"
curl -s -X POST "${BASE_URL}/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"apiuser","password":"apipass123","remember":true}' \
    > /dev/null
echo -e "${GREEN}✓ Sent: apiuser / apipass123${NC}\n"

sleep 1

# Test 5: SSH-style login
echo -e "${YELLOW}Test 5: POST to /ssh with credentials${NC}"
curl -s -X POST "${BASE_URL}/ssh" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=sshuser&password=P@ssw0rd!" \
    > /dev/null
echo -e "${GREEN}✓ Sent: sshuser / P@ssw0rd!${NC}\n"

sleep 1

# Test 6: Database admin
echo -e "${YELLOW}Test 6: POST to /phpmyadmin with credentials${NC}"
curl -s -X POST "${BASE_URL}/phpmyadmin" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "pma_username=dbadmin&pma_password=dbpass123&server=1" \
    > /dev/null
echo -e "${GREEN}✓ Sent: dbadmin / dbpass123${NC}\n"

sleep 1

# Test 7: Multiple fields with email
echo -e "${YELLOW}Test 7: POST to /register with email${NC}"
curl -s -X POST "${BASE_URL}/register" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "email=test@example.com&username=newuser&password=NewPass123&confirm_password=NewPass123" \
    > /dev/null
echo -e "${GREEN}✓ Sent: newuser / NewPass123 (email: test@example.com)${NC}\n"

sleep 1

# Test 8: FTP credentials
echo -e "${YELLOW}Test 8: POST to /ftp/login${NC}"
curl -s -X POST "${BASE_URL}/ftp/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "ftpuser=ftpadmin&ftppass=ftp123456" \
    > /dev/null
echo -e "${GREEN}✓ Sent: ftpadmin / ftp123456${NC}\n"

sleep 1

# Test 9: Common brute force attempt
echo -e "${YELLOW}Test 9: Multiple attempts (simulating brute force)${NC}"
for i in {1..3}; do
    curl -s -X POST "${BASE_URL}/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin&password=pass${i}" \
        > /dev/null
    echo -e "${GREEN}✓ Attempt $i: admin / pass${i}${NC}"
    sleep 0.5
done
echo ""

sleep 1

# Test 10: Special characters in credentials
echo -e "${YELLOW}Test 10: POST with special characters${NC}"
curl -s -X POST "${BASE_URL}/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "username=user@domain.com" \
    --data-urlencode "password=P@\$\$w0rd!#%" \
    > /dev/null
echo -e "${GREEN}✓ Sent: user@domain.com / P@\$\$w0rd!#%${NC}\n"

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ All credential tests completed!${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${YELLOW}Check the results:${NC}"
echo -e "  1. View the log file: ${GREEN}tail -20 logs/credentials.log${NC}"
echo -e "  2. View the dashboard: ${GREEN}${BASE_URL}/dashboard${NC}"
echo -e "  3. Check recent logs: ${GREEN}tail -20 logs/access.log ${NC}\n"

# Display last 10 credential entries if log file exists
if [ -f "src/logs/credentials.log" ]; then
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Last 10 Captured Credentials:${NC}"
    echo -e "${BLUE}========================================${NC}"
    tail -10 src/logs/credentials.log
    echo ""
fi

echo -e "${YELLOW}💡 Tip: Open ${BASE_URL}/dashboard in your browser to see the credentials in real-time!${NC}"
