#!/bin/bash

# Check if the platform parameter is provided
if [ -z "$1" ]; then
  echo "Error: No platform specified. Use 'amd64' or 'arm64'."
  exit 1
fi

# Validate the platform parameter
PLATFORM=$1
if [ "$PLATFORM" != "amd64" ] && [ "$PLATFORM" != "arm64" ]; then
  echo "Error: Invalid platform specified. Use 'amd64' or 'arm64'."
  exit 1
fi

# Path to the pyproject.toml file
PYPROJECT_TOML="./pyproject.toml"

# Extract the version from the pyproject.toml file
VERSION=$(grep '^version *= *"' pyproject.toml | head -1 | cut -d '"' -f2)
# Check if the version was extracted successfully
if [ -z "$VERSION" ]; then
  echo "Error: Could not extract version from $PYPROJECT_TOML"
  exit 1
fi

# Build the Docker image with the extracted version and specified platform
echo "Building Docker image with version: $VERSION for platform: $PLATFORM"
# Build and tag the image for the remote registry (existing behavior)
docker buildx build --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") --platform linux/$PLATFORM -t ekoindarto/lfs:"$VERSION"-$PLATFORM --load .

# Also create a local, convenience tag matching the project image name and version
# so docker-compose and local workflows can reference `rda-service:$VERSION`.
# Use a plain docker build to ensure a locally tagged image is present.
# Note: this will perform a local build (fast layer reuse) but does not affect the remote tag above.
if docker build -t lfs:"$VERSION" .; then
  echo "Tagged local image as lfs:$VERSION"
else
  echo "Warning: failed to create local tag lfs:$VERSION; remote build may still have succeeded."
fi
