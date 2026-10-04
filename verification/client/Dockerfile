FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock
COPY tools ./tools
RUN python tools/fetch_frp.py frpc
COPY shared ./shared
COPY client ./client
COPY DOCS.md ./DOCS.md
COPY run.sh /run.sh
RUN chmod 755 /run.sh
HEALTHCHECK --interval=30s --timeout=5s --start-period=240s CMD ["python", "tools/healthcheck.py"]
CMD ["/run.sh"]
