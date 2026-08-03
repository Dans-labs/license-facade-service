#!/bin/bash

# Quick Start Script for License Facade Service with Fuseki
# This script starts both services using Docker Compose

set -e

echo "=========================================="
echo "License Facade Service + Fuseki"
echo "=========================================="
echo ""

# Check if docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in PATH"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if docker-compose is available (try both v1 and v2)
DOCKER_COMPOSE=""
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
elif docker compose version &> /dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
else
    echo "❌ Docker Compose is not installed"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✓ Docker found: $(docker --version)"
echo "✓ Docker Compose found: $($DOCKER_COMPOSE version --short 2>/dev/null || echo 'installed')"
echo ""

# Create .env if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from .env.example..."
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "✓ .env created. You can edit it to customize settings."
    else
        echo "⚠ .env.example not found. Using default environment variables."
    fi
    echo ""
fi

# Stop existing containers if running
echo "🛑 Stopping existing containers (if any)..."
$DOCKER_COMPOSE down 2>/dev/null || true
echo ""

# Pull latest images
echo "📥 Pulling latest images..."
$DOCKER_COMPOSE pull
echo ""

# Build the application
echo "🔨 Building license-facade-service..."
$DOCKER_COMPOSE build
echo ""

# Start services
echo "🚀 Starting services..."
$DOCKER_COMPOSE up -d
echo ""

# Wait a bit for services to start
echo "⏳ Waiting for services to initialize..."
sleep 5

# Check service status
echo ""
echo "📊 Service Status:"
echo "===================="
$DOCKER_COMPOSE ps
echo ""

# Display URLs
echo "🌐 Service URLs:"
echo "===================="
echo "License Facade Service:"
echo "  → API: http://localhost:12104/api/v1"
echo "  → Docs: http://localhost:12104/docs"
echo ""
echo "Apache Jena Fuseki:"
echo "  → Web UI: http://localhost:3030"
echo "  → Dataset: http://localhost:3030/dataset.html?tab=query&ds=/licenses"
echo ""

# Display log commands
echo "📋 Useful Commands:"
echo "===================="
echo "View logs (all):          $DOCKER_COMPOSE logs -f"
echo "View logs (LFS):          $DOCKER_COMPOSE logs -f license-facade-service"
echo "View logs (Fuseki):       $DOCKER_COMPOSE logs -f fuseki"
echo "Stop services:            $DOCKER_COMPOSE stop"
echo "Stop and remove:          $DOCKER_COMPOSE down"
echo "Restart services:         $DOCKER_COMPOSE restart"
echo "Rebuild and restart:      $DOCKER_COMPOSE up -d --build"
echo ""

# Offer to tail logs
echo "Would you like to view the logs now? (y/n)"
read -t 10 -n 1 -r REPLY || REPLY='n'
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📜 Tailing logs (press Ctrl+C to exit)..."
    echo ""
    $DOCKER_COMPOSE logs -f
else
    echo "✅ Services started successfully!"
    echo ""
    echo "To view logs later, run:"
    echo "  $DOCKER_COMPOSE logs -f"
    echo ""
    echo "The License Facade Service will automatically:"
    echo "  1. Download latest SPDX licenses"
    echo "  2. Transform them to RDF format"
    echo "  3. Upload to Fuseki"
    echo "  4. Be ready to serve requests"
    echo ""
    echo "Check initialization progress with:"
    echo "  $DOCKER_COMPOSE logs -f license-facade-service"
fi

