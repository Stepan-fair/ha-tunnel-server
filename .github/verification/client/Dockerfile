FROM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS frp-builder
COPY tools/build_frp.sh /build-frp.sh
RUN sh /build-frp.sh
FROM python:3.13.18-slim-trixie@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock
COPY tools ./tools
COPY --from=frp-builder /out/frpc /usr/local/bin/frpc
COPY --from=frp-builder /out/LICENSE /out/go.mod /out/go.sum /out/frpc-build.txt /out/frpc-vulncheck.txt /usr/share/doc/frp/
COPY --from=frp-builder /out/licenses /usr/share/doc/frp/licenses
COPY --from=frp-builder /out/module-notices.txt /usr/share/doc/frp/
COPY shared ./shared
COPY client ./client
COPY DOCS.md ./DOCS.md
COPY run.sh /run.sh
RUN chmod 755 /run.sh
HEALTHCHECK --interval=30s --timeout=5s --start-period=240s CMD ["python", "tools/healthcheck.py"]
CMD ["/run.sh"]
