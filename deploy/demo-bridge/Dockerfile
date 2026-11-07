# The demo bridge (D1b): WebSocket to TCP for MQTT, Python standard library only (bridge.py).
#
#   docker build -t urmqtt-demo-bridge deploy/demo-bridge
#
# The base image is pinned by digest, like the mirror's nginx (scripts/mirror/urmqtt-mirror-web.service):
# the multi-architecture index of python:3.12-alpine as Docker Hub served it on 2026-11-07 (OpenSSF Scorecard
# PinnedDependencies, docs/audit/codeql-triage.md). Dependabot (docker, /deploy/demo-bridge) proposes newer
# digests. To build on another one, pass `--build-arg PYTHON_IMAGE=python:3.12-alpine@sha256:<digest>`.
#
# The image holds bridge.py and nothing else: no secrets, no configuration files (everything is DEMO_BRIDGE_*
# environment variables or options), no shell history, a non-root user. Run it read-only with no capabilities
# (the docker run line is in deploy/demo-bridge/urmqtt-demo-bridge.service and docs/DEPLOY.md, section 11).
ARG PYTHON_IMAGE=python:3.12-alpine@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7
FROM ${PYTHON_IMAGE}

RUN adduser -D -H -u 10001 -s /sbin/nologin bridge
COPY --chown=root:root --chmod=0444 bridge.py /app/bridge.py

USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DEMO_BRIDGE_LISTEN=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python3", "-I", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status == 200 else 1)"]
ENTRYPOINT ["python3", "-I", "/app/bridge.py"]
