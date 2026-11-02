# The demo bridge (D1b): WebSocket to TCP for MQTT, Python standard library only (bridge.py).
#
#   docker build -t urmqtt-demo-bridge deploy/demo-bridge
#
# PIN THE BASE IMAGE BY DIGEST before the first real build, like the mirror's nginx (scripts/mirror/
# urmqtt-mirror-web.service): `docker pull python:3.12-alpine`, read `docker inspect --format
# '{{index .RepoDigests 0}}' python:3.12-alpine`, and build with
# `--build-arg PYTHON_IMAGE=python@sha256:<digest>`. The tag below is what was available when this was written;
# this file has not been built by its author (no image was pulled or built for the D1 commit).
#
# The image holds bridge.py and nothing else: no secrets, no configuration files (everything is DEMO_BRIDGE_*
# environment variables or options), no shell history, a non-root user. Run it read-only with no capabilities
# (the docker run line is in deploy/demo-bridge/urmqtt-demo-bridge.service and docs/DEPLOY.md, section 11).
ARG PYTHON_IMAGE=python:3.12-alpine
FROM ${PYTHON_IMAGE}

RUN adduser -D -H -u 10001 -s /sbin/nologin bridge
COPY --chown=root:root --chmod=0444 bridge.py /app/bridge.py

USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DEMO_BRIDGE_LISTEN=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python3", "-I", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status == 200 else 1)"]
ENTRYPOINT ["python3", "-I", "/app/bridge.py"]
