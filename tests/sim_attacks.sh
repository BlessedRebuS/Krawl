#!/bin/bash
TARGET="http://localhost:5000"

echo "=== Testing Path Traversal ==="
curl -s "$TARGET/../../etc/passwd"

echo -e "\n=== Testing SQL Injection ==="
curl -s -X POST "$TARGET/login" -d "user=' OR 1=1--"

echo -e "\n=== Testing XSS ==="
curl -s -X POST "$TARGET/comment" -d "msg=<script>alert(1)</script>"

echo -e "\n=== Testing Common Probes ==="
curl -s "$TARGET/.env"
curl -s "$TARGET/wp-admin/"

echo -e "\n=== Testing Shell Injection ==="
curl -s -X POST "$TARGET/ping" -d "host=127.0.0.1; cat /etc/passwd"

echo -e "\n=== Done ==="