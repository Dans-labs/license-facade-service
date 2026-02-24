FROM python:3.12.8-bookworm
LABEL authors="Eko Indarto"

ARG BUILD_DATE
ENV BUILD_DATE=$BUILD_DATE


# Combine apt-get commands to reduce layers
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends git curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash akmi

ENV PYTHONPATH=/home/akmi/lfs/src
ENV BASE_DIR=/home/akmi/lfs

WORKDIR ${BASE_DIR}


# Install uv.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy the application into the container.


# Create and activate virtual environment
RUN python -m venv .venv
ENV APP_NAME="ost-clarin-skg"
ENV PATH="/home/akmi/lfs/.venv/bin:$PATH"
# Copy the application into the container.
COPY src ./src
#Temporary, will be removed later
COPY conf ./conf
COPY pyproject.toml .
COPY README.md .
COPY uv.lock .


# Install dependencies

RUN uv sync --frozen --no-cache && chown -R akmi:akmi ${BASE_DIR}
USER akmi
RUN mkdir logs
# Run the application.
CMD ["python", "-m", "src.license_facade_service.main"]

#CMD ["tail", "-f", "/dev/null"]