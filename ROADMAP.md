# Roadmap

## Current Status (v0.1.0)

The WAF agent is functional for **request inspection in buffer mode**. It correctly implements the `sentinel-agent-protocol` (v0.1.x) and can detect/block common web attacks in request headers and bodies.

### What Works

- Request header inspection (path, query string, all headers)
- Request body inspection (JSON, form data, all content types)
- Response body inspection (reflected XSS, error leakage detection)
- SQL injection, XSS, path traversal, command injection detection
- Paranoia levels 1-4 for tuning sensitivity
- Block mode and detect-only mode
- Path exclusions
- Configurable max body size (default 1MB)

### What Doesn't Work

- Streaming mode (always buffers full body)
- WebSocket frame inspection
- Progressive/incremental decisions on large bodies
- Body content modification (can only block/allow)

---

## Roadmap

### v0.2.0 - Response Inspection ✓

**Status: Complete**

Added response body inspection to detect attacks in server responses (e.g., reflected XSS, error message leakage).

- [x] Implement `on_response_body_chunk()` handler
- [x] Add `--response-inspection` flag (default: false for backward compat)
- [x] Reuse existing detection rules for response bodies
- [x] Add tests for response body inspection

### v0.3.0 - Streaming Mode Support

**Priority: High**

Support streaming mode for memory efficiency on large request bodies.

- [ ] Implement incremental body scanning (don't wait for `is_last`)
- [ ] Support `needs_more` flag for progressive decisions
- [ ] Add `--streaming-mode` flag (buffer | stream | hybrid)
- [ ] Optimize memory usage for large bodies
- [ ] Add benchmarks comparing buffer vs streaming performance

### v0.4.0 - Integration Tests

**Status: Complete**

Added integration tests using the sentinel-agent-protocol's AgentClient/AgentServer for end-to-end testing without requiring a full Sentinel proxy deployment.

- [x] Create integration test harness using AgentClient/AgentServer
- [x] Test SQL injection detection (query string, UNION SELECT, detect-only mode)
- [x] Test XSS detection (script tags, event handlers, JavaScript URIs, headers)
- [x] Test path traversal detection (plain and URL-encoded)
- [x] Test command injection detection (backticks, pipes)
- [x] Test path exclusion functionality
- [x] Test request body inspection (single chunk, chunked, size limits)
- [x] Test response body inspection
- [x] Test scanner detection
- [x] Test paranoia levels (level 1 vs level 2)
- [x] Test clean requests pass through
- [ ] Add CI workflow for integration tests (future)

### v0.5.0 - WebSocket Support

**Priority: Medium**

Add WebSocket frame inspection for detecting attacks in WebSocket traffic.

- [ ] Implement `on_websocket_frame()` handler
- [ ] Add WebSocket-specific detection rules (if applicable)
- [ ] Add `--websocket-inspection` flag
- [ ] Add tests for WebSocket inspection

### v0.6.0 - Advanced Features

**Priority: Low**

- [ ] Body content modification (sanitize instead of block)
- [ ] Custom rule support (user-defined regex patterns)
- [ ] Rule exclusions by ID
- [ ] JSON/XML-aware parsing for structured body inspection
- [ ] Rate limiting integration (track repeat offenders)

---

## Non-Goals

These are explicitly out of scope:

- **Full OWASP CRS compatibility** - We implement a useful subset, not the full ruleset
- **ModSecurity rule language** - We use native Rust regex, not SecLang
- **Learning mode / ML-based detection** - Keep it simple and deterministic

---

## Compatibility

| Sentinel Version | WAF Agent Version | Status |
|------------------|-------------------|--------|
| 0.1.x | 0.1.x | Supported |

The agent depends on `sentinel-agent-protocol = "0.1"` and should remain compatible with any Sentinel 0.1.x release.

---

## Contributing

When working on new features:

1. Add unit tests for new detection rules
2. Update README.md with new CLI options
3. Update this ROADMAP.md when completing milestones
4. Run `cargo test && cargo clippy && cargo fmt` before committing
