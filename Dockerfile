# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS build
WORKDIR /src
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install .

FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# Docker CLI only (no daemon) for the docker_* tools; talks to a mounted socket or DOCKER_HOST.
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=build /opt/venv /opt/venv

RUN useradd --create-home --uid 10001 devtools  && mkdir -p /data /config  && chown devtools /data
USER devtools
WORKDIR /home/devtools

# Mounted repositories are owned by another uid; let git read them.
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=safe.directory \
    GIT_CONFIG_VALUE_0=* \
    MCP_DEVTOOLS_CONFIG=/config/devtools.yaml

EXPOSE 8765
ENTRYPOINT ["mcp-devtools"]
CMD ["serve", "--transport", "http", "--host", "0.0.0.0", "--port", "8765"]
