FROM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS frp-builder
COPY tools/build_frp.sh /build-frp.sh
RUN sh /build-frp.sh
FROM python:3.13-slim-trixie@sha256:3dd7cc108ec1493442514f5c2a871af6af0ec31d768ff6e378a93340c3b3db5f
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
