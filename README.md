# sentinel-agent-waf

Web Application Firewall agent for [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy. Detects and blocks common web attacks.

## Features

- **SQL Injection detection** - UNION-based, blind, time-based
- **Cross-Site Scripting (XSS)** - Script tags, event handlers, JavaScript URIs
- **Path Traversal** - Directory traversal, encoded attacks
- **Command Injection** - Shell commands, pipe injection
- **Protocol Attacks** - Request smuggling, scanner detection
- **Request Body Inspection** - JSON, form data, and all content types
- **Paranoia levels** (1-4) for tuning sensitivity
- **Detect-only mode** for monitoring without blocking

## Installation

### From crates.io

```bash
cargo install sentinel-agent-waf
```

### From source

```bash
git clone https://github.com/raskell-io/sentinel-agent-waf
cd sentinel-agent-waf
cargo build --release
```

## Usage

```bash
sentinel-waf-agent --socket /var/run/sentinel/waf.sock --paranoia-level 1
```

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/sentinel-waf.sock` |
| `--paranoia-level` | `WAF_PARANOIA_LEVEL` | Sensitivity (1-4) | `1` |
| `--sqli` | `WAF_SQLI` | Enable SQL injection detection | `true` |
| `--xss` | `WAF_XSS` | Enable XSS detection | `true` |
| `--path-traversal` | `WAF_PATH_TRAVERSAL` | Enable path traversal detection | `true` |
| `--command-injection` | `WAF_COMMAND_INJECTION` | Enable command injection detection | `true` |
| `--protocol` | `WAF_PROTOCOL` | Enable protocol attack detection | `true` |
| `--block-mode` | `WAF_BLOCK_MODE` | Block (true) or detect-only (false) | `true` |
| `--exclude-paths` | `WAF_EXCLUDE_PATHS` | Paths to exclude (comma-separated) | - |
| `--body-inspection` | `WAF_BODY_INSPECTION` | Enable request body inspection | `true` |
| `--max-body-size` | `WAF_MAX_BODY_SIZE` | Maximum body size to inspect (bytes) | `1048576` (1MB) |
| `--verbose` | `WAF_VERBOSE` | Enable debug logging | `false` |

## Paranoia Levels

| Level | Description |
|-------|-------------|
| 1 | High-confidence detections only (recommended for production) |
| 2 | Adds medium-confidence rules, more false positives possible |
| 3 | Adds low-confidence rules, requires tuning |
| 4 | Maximum sensitivity, expect false positives |

## Detection Rules

### SQL Injection (942xxx)
- UNION-based injection
- Tautology attacks (`OR 1=1`)
- Comment injection (`--`, `#`, `/**/`)
- Time-based blind injection (`SLEEP()`, `BENCHMARK()`)

### Cross-Site Scripting (941xxx)
- Script tag injection (`<script>`)
- Event handler injection (`onclick=`, `onerror=`)
- JavaScript URI (`javascript:`)
- Data URI (`data:text/html`)

### Path Traversal (930xxx)
- Directory traversal (`../`, `..\\`)
- URL-encoded traversal (`%2e%2e%2f`)
- OS file access (`/etc/passwd`, `c:\\windows`)

### Command Injection (932xxx)
- Shell command injection (`; ls`, `| cat`)
- Unix command execution (`$(...)`, backticks)
- Windows command execution (`cmd.exe`, `powershell`)

### Protocol Attacks (920xxx)
- Control characters in request
- Request smuggling patterns
- Scanner detection (Nikto, SQLMap, etc.)

## Configuration

### Sentinel Proxy Configuration

```kdl
agents {
    agent "waf" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/sentinel/waf.sock"
        }
        events ["request_headers", "request_body_chunk"]
        timeout-ms 50
        failure-mode "open"
    }
}

routes {
    route "all" {
        matches { path-prefix "/" }
        upstream "backend"
        agents ["waf"]
    }
}
```

### Docker/Kubernetes

```yaml
# Environment variables
WAF_PARANOIA_LEVEL: "1"
WAF_BLOCK_MODE: "true"
WAF_EXCLUDE_PATHS: "/health,/metrics"
```

## Response Headers

On blocked requests:
- `X-WAF-Blocked: true`
- `X-WAF-Rule: <rule_id>`

In detect-only mode, the request continues but includes:
- `X-WAF-Detected: <rule_ids>`

## Excluding Paths

Exclude paths from WAF inspection:

```bash
sentinel-waf-agent --exclude-paths "/health,/metrics,/static"
```

## False Positive Handling

1. **Lower paranoia level** - Start with level 1 and increase gradually
2. **Exclude paths** - Exclude known-safe endpoints
3. **Detect-only mode** - Monitor before enabling blocking
4. **Custom rules** - Future feature for rule customization

## Comparison with ModSecurity

This agent provides a subset of ModSecurity's OWASP CRS functionality:

| Feature | This Agent | ModSecurity |
|---------|------------|-------------|
| SQL Injection | ✓ | ✓ |
| XSS | ✓ | ✓ |
| Path Traversal | ✓ | ✓ |
| Command Injection | ✓ | ✓ |
| Full CRS Ruleset | Partial | ✓ |
| Body Inspection | ✓ | ✓ |
| Custom Rules | - | ✓ |
| Dependencies | Pure Rust | libmodsecurity |
| Installation | `cargo install` | Complex |

For full OWASP CRS compatibility, consider using ModSecurity with Sentinel's external processing.

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run -- --socket /tmp/test.sock --paranoia-level 2

# Run tests
cargo test
```

## License

MIT OR Apache-2.0
