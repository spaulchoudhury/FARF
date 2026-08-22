# FARF containerised deployment image.
# Built from the repository root (see docker-compose.yml: build.context: ..).
# One image is reused for every service (federation-bus, org-a, org-b,
# org-c); which entrypoint script runs is selected per-service by
# docker-compose's `command:`, so the FARF codebase itself is identical
# across every container -- only the network role differs, which is the
# point being demonstrated (the same, unmodified artefacts from Chapter 5
# running as genuinely separate organisational processes).

FROM python:3.11-slim

WORKDIR /app

COPY docker/requirements-docker.txt /app/docker/requirements-docker.txt
RUN pip install --no-cache-dir -r /app/docker/requirements-docker.txt

# Copy the full FARF prototype (Chapter 5's artefacts, unmodified) plus
# the docker/ shim built in this session.
COPY . /app

RUN mkdir -p /data

ENV PYTHONUNBUFFERED=1

# No default CMD: docker-compose.yml specifies bus_service.py for the
# federation-bus service and org_client.py for each org-* service.
