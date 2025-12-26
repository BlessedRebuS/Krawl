#!/bin/env bash
# -s is for silent (no progress bar) | -I is to get the headers | grep is to find only the Server line
curl -s -I http://localhost:5000 | grep "Server:"