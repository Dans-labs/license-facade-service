# License Facade Service

A centralized service that enables end users, data publishers, and developers to unambiguously identify, reference, validate, and retrieve information about dataset licenses.

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.131.0+-green.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)](https://www.docker.com/)

## 🌐 Demo

Try the live demo: [https://lfs.labs.dansdemo.nl/docs](https://lfs.labs.dansdemo.nl/docs)

## 📋 Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Testing](#-testing)
- [Development](#development)
- [Docker Deployment](#docker-deployment)
- [License](#license)

## ✨ Features

- **License Information Retrieval**: Get detailed information about dataset licenses
- **Multiple License Formats**: Support for JSON, machine-readable, legal text, and original formats
- **RESTful API**: FastAPI-based REST API with automatic OpenAPI documentation
- **Health Monitoring**: Built-in health check and ping endpoints
- **Intelligent Caching**: Automatic caching of SPDX license data with version tracking
  - Downloads all licenses on first run or when SPDX updates
  - Serves from local cache for fast response times
  - Automatic update checks on startup
  - Manual cache refresh endpoints
- **Docker Support**: Ready-to-deploy Docker container with docker-compose
- **Logging**: Comprehensive logging with daily rotation
- **CORS Support**: Configurable CORS for cross-origin requests

## 🔧 Prerequisites

- Python 3.12 or higher
- [uv](https://github.com/astral-sh/uv) package manager
- Docker and Docker Compose (for containerized deployment)

## 📦 Installation

### Using uv (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd license-facade-service

# Install dependencies
uv sync

# Activate virtual environment
source .venv/bin/activate
```

### Using pip

```bash
# Clone the repository
git clone <repository-url>
cd license-facade-service

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## ⚙️ Configuration

Configuration is managed through `conf/settings.toml`:

```toml
[default]
api_prefix = "/api/v1"
expose_port = 1912
reload_enable = true

# Logging
log_level = 10
log_file = "@format {env[BASE_DIR]}/logs/lfs.log"
log_format = '%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s'

# CORS
cors_origins = ["*"]

# Database
db_dialect = "postgresql+psycopg2"

# Other
otlp_enable = false
```

### Environment Variables

- `APP_NAME`: Application name (default: "OSTrails Clarin SKG-IF Service")
- `EXPOSE_PORT`: Port to expose the service (default: 12104)
- `BASE_DIR`: Base directory for the application
- `BUILD_DATE`: Build date for version tracking
- `URL_BASE`: Base URL for license URIs (default: "https://lfs.labs.dansdemo.nl/api/v1/licenses")

## 🚀 Usage

### Running Locally

```bash
# Set environment variables
export BASE_DIR=$(pwd)
export EXPOSE_PORT=12104

# Run the service
python -m src.license_facade_service.main
```

The service will be available at:
- API: `http://localhost:12104`
- Interactive API docs: `http://localhost:12104/docs`
- ReDoc: `http://localhost:12104/redoc`

## 📚 API Endpoints

### Health & Monitoring

- `GET /health` - Health check endpoint
- `GET /ping` - Simple ping/pong endpoint

### License Endpoints

- `GET /licenses` - List all available licenses with complete details (from cache)
- `GET /licenses/{id}` - **Human-readable HTML landing page** for a license (DEFAULT)
  - Supports:
    - License ID: `MIT`, `0BSD`, `Apache-2.0`
    - UUID only: `d1b405f5-98e2-5acd-9f7b-531983fb5aad` (recommended - cleanest URLs)
    - UUID with path: `d1b405f5-98e2-5acd-9f7b-531983fb5aad/details`
    - Full URI: `https://lfs.labs.dansdemo.nl/api/v1/licenses/d1b405f5-98e2-5acd-9f7b-531983fb5aad`
  - Returns: Beautiful HTML landing page with license metadata, approval status, and links
  - Content-Type: `text/html`
- `GET /licenses/{id}/json` - Get detailed license information in JSON format (includes full license text and templates)
- `GET /licenses/{id}/original` - Get original license text (plain text)
- `GET /licenses/{id}/machine` - Get machine-readable license format
- `GET /licenses/{id}/legal` - Get legal text for the license (plain text)

### Endpoint Format Notes

- **`/licenses/{id}`** - Returns **HTML landing page** (web browser friendly)
  - Perfect for viewing in a web browser
  - Shows all license metadata with nice formatting
  - Includes approval status and links to other formats

- **`/licenses/{id}/json`** - Returns **JSON** (programmatic access)
  - Use when you need structured data
  - Same metadata as HTML landing page
  - Perfect for API integration

### Cache Management Endpoints

- `GET /licenses/cache/status` - Get cache status, version, and last update time
- `POST /licenses/cache/update` - Check for updates and download if new version available
- `POST /licenses/cache/refresh` - Force refresh cache regardless of version

### Example Usage

```bash
# Health check
curl http://localhost:12104/health

# Check cache status
curl http://localhost:12104/licenses/cache/status

# Get all licenses
curl http://localhost:12104/licenses | jq '.licenses | length'

# Get license information by License ID
curl http://localhost:12104/licenses/AFL-1.1
# Returns: Complete license metadata with URI

# Get license information by UUID (NEW - RECOMMENDED!)
# Extract UUID from any license's URI and search directly
curl http://localhost:12104/licenses/d1b405f5-98e2-5acd-9f7b-531983fb5aad
# Returns: Same license data as by ID search

# Get license information by Full URI (also supported)
URI="https://lfs.labs.dansdemo.nl/api/v1/licenses/550e8400-..."
curl "http://localhost:12104/licenses/$(python3 -c "import urllib.parse; print(urllib.parse.quote('$URI', safe=''))")"

# Get license information by URI
URI="https://lfs.labs.dansdemo.nl/api/v1/licenses/550e8400-..."
curl "http://localhost:12104/licenses/$(python3 -c "import urllib.parse; print(urllib.parse.quote('$URI', safe=''))")"
# Returns: Same license data as above

# Get detailed license JSON (includes full text and templates)
curl http://localhost:12104/licenses/MIT/json

# Get license text
curl http://localhost:12104/licenses/Apache-2.0/original

# Update cache if new version available
curl -X POST http://localhost:12104/licenses/cache/update

# Force refresh cache
curl -X POST http://localhost:12104/licenses/cache/refresh
```

## 🧪 Testing

This project includes a suite of Python tests for license retrieval, caching, URI generation, RDF transformation, and Fuseki integration.

All commands below assume you are in the project root (`license-facade-service`) and have installed dependencies as described in the [Installation](#installation) section.

### Run all tests (recommended)

Using `uv` and `pytest`:

```bash
# Install dependencies (if not done yet)
uv sync

# Run the test suite
uv run pytest
```

Or, from an activated virtual environment:

```bash
source .venv/bin/activate
pytest
```

If you prefer the built-in unittest discovery:

```bash
python -m unittest discover -p "test_*.py"
```

### Run individual tests

You can also run specific test modules directly. For example:

```bash
# License API tests
python test_licenses_api.py

# Cache system tests
python test_cache_system.py

# Fuseki integration tests (requires Fuseki running via Docker)
python test_fuseki_integration.py

# RDF transformer tests
python test_rdf_transformer.py
```

Some tests (such as Fuseki integration) require the Docker services to be running. See the [Docker Deployment](#docker-deployment) section for how to start the stack.

## 🛠️ Development

### Project Structure

```
license-facade-service/
├── src/
│   └── license_facade_service/
│       ├── main.py              # Application entry point
│       ├── api/
│       │   └── v1/
│       │       ├── licenses.py  # License endpoints
│       │       └── metrics.py   # Health/monitoring endpoints
│       ├── infra/               # Infrastructure components
│       └── utils/
│           └── commons.py       # Common utilities
├── conf/
│   └── settings.toml            # Configuration file
├── logs/                        # Application logs
├── docker-compose.yaml          # Docker Compose configuration
├── Dockerfile                   # Docker build configuration
├── pyproject.toml              # Project metadata and dependencies
└── README.md
```

### Running Tests

For detailed testing instructions (running all tests or targeted tests), see the [Testing](#-testing) section above.

### Code Style

The project follows Python best practices and uses:
- **UV** for fast, modern Python package management
- FastAPI for API development
- Dynaconf for configuration management
- Uvicorn for ASGI server

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)

```bash
# Build and start the service
docker compose up --build

# Run in detached mode
docker compose up -d

# View logs
docker compose logs -f

# Stop the service
docker compose down
```

### Using Docker directly

```bash
# Build the image
docker build -t lfs --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") .

# Run the container
docker run -d \
  --name lfs \
  -p 1912:1912 \
  -v $(pwd)/conf:/home/akmi/lfs/conf:ro \
  -v $(pwd)/logs:/home/akmi/lfs/logs \
  -e APP_NAME="License Facade Service" \
  -e EXPOSE_PORT=1912 \
  -e BASE_DIR=/home/akmi/lfs \
  lfs
```

### Docker Configuration

The `docker-compose.yaml` provides:
- Automatic image building from Dockerfile
- Port mapping (1912:1912)
- Volume mounts for configuration and logs
- Environment variable configuration
- Restart policy (unless-stopped)

### Customizing Docker Deployment

You can override default settings using environment variables:

```bash
# Using .env file
echo "EXPOSE_PORT=8080" > .env
echo "APP_NAME=My License Service" >> .env
docker compose up
```

## 📝 License

[Add your license information here]

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Contact

For questions or support, please open an issue in the repository.

---

**Note**: This service is part of the OSTrails Clarin SKG-IF ecosystem.
