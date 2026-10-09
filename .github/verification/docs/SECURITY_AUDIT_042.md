# Security and reliability review for 0.4.2

## Confirmed fixes

- FRP remains at the same upstream 0.71.0 source/protocol, rebuilt with digest-pinned Go 1.26.9. The [official 8 October security release](https://go.dev/doc/devel/release) fixes TLS/HTTP/runtime issues; compiled Server/Client binaries are checked by govulncheck during isolated Linux builds.

- aiohttp 3.14.3 is affected by newly published resource-exhaustion advisories. Both hash-locked dependency files now select 3.14.4. Official sources: [memory/CPU exhaustion](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-2g87-pp6c-29x5), [multipart file descriptor exhaustion](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-9xw5-w5jj-pvcg). The latter advisory has inconsistent affected/patched version metadata; the endpoint mitigation also rejects multipart before parsing.
- The OAuth token endpoint accepted multipart file uploads despite requiring only an OAuth form. A local regression confirmed this acceptance. It now returns 415 before creating temporary files; URL-encoded OAuth remains supported.
- Background monitoring could overlap credential replacement. A delayed-response regression reproduced the overlap. The controller now serializes these operations so an old response cannot overwrite the replacement's state.
- Status polling unnecessarily recreated its HTTP/TLS session and accepted cookies. Real verified-TLS tests now confirm connection reuse, per-request authorization, cookie rejection, redirect rejection and explicit cleanup. The pool is bounded to two connections, keepalive 45 seconds.
- Telemetry had a socket semaphore but allocated one task per client. A 24-client regression confirmed 24 waiting tasks. It now uses at most eight workers and still visits every client; deleted-client samples are pruned.

## Threat checks and existing controls

| Area | Controls and verification |
| --- | --- |
| Authentication/IDOR | Separate public, Ingress and loopback surfaces; actual HA admin verification per request; individual hashed client credentials; server-authoritative pause/revoke/generation. HTTP/API, access, reenrollment and real FRP regressions. |
| CSRF/XSS | Per-user HMAC CSRF on mutations; restrictive CSP; textContent/DOM construction; no dynamic HTML evaluation in product scripts. Admin/asset/command regressions. |
| HTTP smuggling/host routing | Reject duplicate framing, CL+TE, invalid chunks, absolute request targets and cross-host pipelines; one HTTP request per connection; generation-specific internal upstream. Relay and Nginx integration tests. |
| WebSocket | Same access checks before upgrade; reject unexpected upgrades; bounded handshake/greeting; pause closes only the selected client's streams. Existing WebSocket and real FRP tests. |
| SSRF | Canonical HTTPS registration origin; no redirects/ambient proxy for credentialed calls; internal NPM resolver restricts destination; loopback probes and fixed upstream. Enrollment/network/redirect regressions. |
| Resource exhaustion | Body/time/IP/client/concurrent-lane bounds, CGNAT reserve, bounded relay streams/backpressure, bounded diagnostic files; new multipart and worker regressions. |
| Archives | Encrypted backup, strict member whitelist/type/size limits, staged atomic restore; revoked identities cannot be revived from old backups. Backup/archive regressions. |
| Secrets | Templates/static assets contain no runtime secrets; state excludes credential/private-key fields; diagnostics allow structured fields rather than exception messages/request bodies; FRP child environment excludes Supervisor credentials. Admin/API/log/packaging checks. |

Review references: [OWASP request smuggling](https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling), [OWASP SSRF](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [OWASP WebSocket](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html).

## Scope and evidence limits

This review does not prove the absence of every vulnerability. The trusted Server/NPM can access proxied plaintext by design. An operator with root/data-backup access can access stored private credentials. Public CA certificates, JWKS public keys and per-user CSRF tokens are not private keys. Enrollment credentials and explicitly requested one-use invitations are delivered only through their intended authenticated/one-use flows.

Windows regression results, fresh Linux integration/image scan results, exact published-image verification and live before/after acceptance are recorded in release evidence after execution. Skipped Linux tests do not satisfy the release gate; unfixed base-image advisories must remain visible in the full scan report.
