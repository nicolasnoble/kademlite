FROM python:3.12-slim

RUN pip install --no-cache-dir cryptography "protobuf>=5.27.0,<6.0.0"

# kubectl for soak test (rollout restart)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sLo /usr/local/bin/kubectl \
       "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && chmod +x /usr/local/bin/kubectl \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Install kademlite from source. Build context is the repo root so we copy the
# package directory plus the metadata files that pyproject's license-files refers to.
COPY kademlite/ kademlite_pkg/kademlite/
COPY pyproject.toml LICENSE-MIT LICENSE-APACHE AUTHORS README.md kademlite_pkg/
RUN pip install --no-cache-dir ./kademlite_pkg/

COPY tests/k8s/k8s_dht_runner.py .

ENTRYPOINT ["python", "k8s_dht_runner.py"]
