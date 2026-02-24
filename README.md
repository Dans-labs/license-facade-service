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
- [Development](#development)
- [Docker Deployment](#docker-deployment)
- [License](#license)

## ✨ Features

- **License Information Retrieval**: Get detailed information about dataset licenses
- **Multiple License Formats**: Support for JSON, machine-readable, legal text, and original formats
- **RESTful API**: FastAPI-based REST API with automatic OpenAPI documentation
- **Health Monitoring**: Built-in health check and ping endpoints
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
- `EXPOSE_PORT`: Port to expose the service (default: 1912)
- `BASE_DIR`: Base directory for the application
- `BUILD_DATE`: Build date for version tracking

## 🚀 Usage

### Running Locally

```bash
# Set environment variables
export BASE_DIR=$(pwd)
export EXPOSE_PORT=1912

# Run the service
python -m src.license_facade_service.main
```

The service will be available at:
- API: `http://localhost:1912`
- Interactive API docs: `http://localhost:1912/docs`
- ReDoc: `http://localhost:1912/redoc`

## 📚 API Endpoints

### Health & Monitoring

- `GET /health` - Health check endpoint
- `GET /ping` - Simple ping/pong endpoint

### License Endpoints

- `GET /licenses` - List all available licenses
- `GET /licenses/{id}` - Get basic license information
- `GET /licenses/{id}/json` - Get detailed license information in JSON format
- `GET /licenses/{id}/original` - Get original license text
- `GET /licenses/{id}/machine` - Get machine-readable license format
- `GET /licenses/{id}/legal` - Get legal text for the license

### Example Usage

```bash
# Health check
curl http://localhost:1912/health

# Get license information
curl http://localhost:1912/licenses/mit

# Get detailed license JSON
curl http://localhost:1912/licenses/mit/json
```

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

```bash
# Run tests (if available)
pytest
```

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
