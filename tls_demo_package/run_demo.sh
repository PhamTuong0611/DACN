#!/usr/bin/env bash
set -e
echo "== Build and run demo (Docker Compose) =="
docker-compose build --no-cache
docker-compose up -d
echo "Waiting 5s for containers to initialize..."
sleep 5
echo "== Containers started. The scanner web UI is available. =="
echo "Open http://localhost:8080 to add domains and run scans from the browser."
