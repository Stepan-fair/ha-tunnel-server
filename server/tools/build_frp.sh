#!/bin/sh
set -eu
# Keep upstream behavior at 0.71.0, replacing only affected toolchain/modules.
export GOTOOLCHAIN=local GOSUMDB=sum.golang.org GOPROXY=https://proxy.golang.org
export CGO_ENABLED=0 GOMAXPROCS=2
curl -fsSL https://codeload.github.com/fatedier/frp/tar.gz/4a23aa181c1d7e28eecaa8216024ed753b9d27c8 -o /tmp/frp-source.tar.gz
printf '%s\n' '6ae290e8aec2ef389b8e12772481e361f330631d070e78d2919295124acbc2c8  /tmp/frp-source.tar.gz' | sha256sum -c -
mkdir -p /src /out
tar xzf /tmp/frp-source.tar.gz --strip-components=1 -C /src
cd /src
go mod edit -require=github.com/Azure/go-ntlmssp@v0.1.1 -require=golang.org/x/crypto@v0.56.0
go mod tidy
# Retain symbols: stripped binaries make govulncheck fall back to whole modules.
go build -p 1 -mod=readonly -trimpath -tags=frps,noweb -o /out/frps ./cmd/frps
go build -p 1 -mod=readonly -trimpath -tags=frpc,noweb -o /out/frpc ./cmd/frpc
cp LICENSE /out/LICENSE
cp go.mod go.sum /out/
mkdir -p /out/licenses/go
cp /usr/local/go/LICENSE /usr/local/go/PATENTS /out/licenses/go/
# Collect notices from the actual linked module graph, including replacements.
go list -deps -mod=readonly -tags=noweb -f '{{if .Module}}{{.Module.Path}}@{{.Module.Version}}|{{if .Module.Replace}}{{.Module.Replace.Dir}}{{else}}{{.Module.Dir}}{{end}}{{end}}' ./cmd/frps ./cmd/frpc > /out/module-notices-unsorted.txt
LC_ALL=C sort -u /out/module-notices-unsorted.txt > /out/module-notices.txt
while IFS='|' read -r identity directory; do
    [ -n "$directory" ] || continue
    name=$(printf '%s' "$identity" | tr '/' '_')
    destination="/out/licenses/$name"
    mkdir -p "$destination"
    (cd "$directory"; find . -type f \( -iname 'license*' -o -iname 'copying*' -o -iname 'notice*' -o -iname 'copyright*' -o -iname 'patents*' \)) | while IFS= read -r notice; do
        relative=${notice#./}
        mkdir -p "$destination/$(dirname "$relative")"
        cp "$directory/$relative" "$destination/$relative"
    done
done < /out/module-notices.txt
go version -m /out/frps > /out/frps-build.txt
go version -m /out/frpc > /out/frpc-build.txt
# Check compiled symbols, rather than treating unused module packages as live.
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -mode=binary /out/frps > /out/frps-vulncheck.txt
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -mode=binary /out/frpc > /out/frpc-vulncheck.txt
