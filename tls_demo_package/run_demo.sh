#!/usr/bin/env bash

echo "================================================"
echo "TLS Security Scanner - Docker Demo Launcher"
echo "================================================"
echo ""

# Check Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ ERROR: Docker is not installed"
    echo "   Please install Docker from: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ ERROR: Docker Compose is not installed"
    echo "   Please install Docker Compose"
    exit 1
fi

echo "✓ Docker and Docker Compose found"
echo ""

# Check if already running
echo "🔍 Checking for existing containers..."
if docker-compose ps 2>/dev/null | grep -q "tls_scanner"; then
    echo "⚠️  Container already running. Stopping..."
    docker-compose down 2>/dev/null || true
fi

echo ""

# Build image
echo "🔨 Building Docker image (this may take 3-5 minutes)..."
echo "   Note: First build is slower. Downloads and installs all packages."
echo ""
if docker-compose build --no-cache 2>&1 | tee /tmp/docker_build.log; then
    echo ""
    echo "✓ Build successful!"
else
    echo ""
    echo "❌ Build failed!"
    echo ""
    echo "Troubleshooting steps:"
    echo "1. Verify Docker is running:"
    echo "   docker info"
    echo ""
    echo "2. Check internet connection:"
    echo "   ping google.com"
    echo ""
    echo "3. Check available disk space:"
    echo "   df -h"
    echo ""
    echo "4. View detailed build logs:"
    echo "   docker-compose build --no-cache 2>&1 | tail -50"
    exit 1
fi
echo ""

# Start container
echo "🚀 Starting scanner container..."
if docker-compose up -d 2>&1; then
    echo "✓ Container started"
else
    echo "❌ Failed to start container"
    docker-compose logs
    exit 1
fi
echo ""

# Wait for container to be ready
echo "⏳ Waiting for scanner to initialize (max 15 seconds)..."
COUNTER=0
MAX_WAIT=15

while [ $COUNTER -lt $MAX_WAIT ]; do
    if docker-compose ps 2>/dev/null | grep -q "tls_scanner.*Up"; then
        echo "✓ Scanner container is running"
        break
    fi
    COUNTER=$((COUNTER + 1))
    if [ $COUNTER -eq $MAX_WAIT ]; then
        echo "❌ Scanner container failed to start"
        echo ""
        echo "Container status:"
        docker-compose ps
        echo ""
        echo "Container logs:"
        docker-compose logs scanner | tail -30
        exit 1
    fi
    sleep 1
done
echo ""

# Show status
echo "================================================"
echo "✅ Scanner is ready!"
echo "================================================"
echo ""
echo "📱 Web UI: http://localhost:8080"
echo ""
echo "💡 Next steps:"
echo "   1. Open http://localhost:8080 in your browser"
echo "   2. Enter domain/URL (e.g., https://google.com)"
echo "   3. Click 'Quét cấu hình' to scan"
echo ""
echo "📋 View logs:"
echo "   docker-compose logs -f scanner"
echo ""
echo "🛑 Stop scanner:"
echo "   docker-compose down"
echo ""
