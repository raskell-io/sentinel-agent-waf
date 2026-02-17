# syntax=docker/dockerfile:1.4

# Zentinel WAF Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-waf-agent /zentinel-waf-agent

LABEL org.opencontainers.image.title="Zentinel WAF Agent" \
      org.opencontainers.image.description="Zentinel WAF Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-waf"

ENV RUST_LOG=info,zentinel_waf_agent=debug \
    SOCKET_PATH=/var/run/zentinel/waf.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-waf-agent"]
