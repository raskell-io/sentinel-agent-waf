//! Sentinel WAF Agent
//!
//! A Web Application Firewall agent for Sentinel proxy that detects and blocks
//! common web attacks including SQL injection, XSS, path traversal, and more.

use anyhow::{anyhow, Result};
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use sentinel_agent_protocol::{
    AgentHandler, AgentResult, AgentServer, Decision, Mutations,
    RequestHeadersEvent, ResponseHeadersEvent,
};

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "sentinel-waf-agent")]
#[command(about = "Web Application Firewall agent for Sentinel reverse proxy")]
struct Args {
    /// Path to Unix socket
    #[arg(long, default_value = "/tmp/sentinel-waf.sock", env = "AGENT_SOCKET")]
    socket: PathBuf,

    /// Paranoia level (1-4, higher = more strict)
    #[arg(long, default_value = "1", env = "WAF_PARANOIA_LEVEL")]
    paranoia_level: u8,

    /// Enable SQL injection detection
    #[arg(long, default_value = "true", env = "WAF_SQLI")]
    sqli: bool,

    /// Enable XSS detection
    #[arg(long, default_value = "true", env = "WAF_XSS")]
    xss: bool,

    /// Enable path traversal detection
    #[arg(long, default_value = "true", env = "WAF_PATH_TRAVERSAL")]
    path_traversal: bool,

    /// Enable command injection detection
    #[arg(long, default_value = "true", env = "WAF_COMMAND_INJECTION")]
    command_injection: bool,

    /// Enable protocol attacks detection
    #[arg(long, default_value = "true", env = "WAF_PROTOCOL")]
    protocol: bool,

    /// Block mode (true) or detect-only mode (false)
    #[arg(long, default_value = "true", env = "WAF_BLOCK_MODE")]
    block_mode: bool,

    /// Paths to exclude from WAF (comma-separated)
    #[arg(long, env = "WAF_EXCLUDE_PATHS")]
    exclude_paths: Option<String>,

    /// Enable verbose logging
    #[arg(short, long, env = "WAF_VERBOSE")]
    verbose: bool,
}

/// Attack type detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackType {
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    ProtocolAttack,
    ScannerDetection,
    RequestSmuggling,
}

impl std::fmt::Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackType::SqlInjection => write!(f, "SQL Injection"),
            AttackType::Xss => write!(f, "Cross-Site Scripting"),
            AttackType::PathTraversal => write!(f, "Path Traversal"),
            AttackType::CommandInjection => write!(f, "Command Injection"),
            AttackType::ProtocolAttack => write!(f, "Protocol Attack"),
            AttackType::ScannerDetection => write!(f, "Scanner Detection"),
            AttackType::RequestSmuggling => write!(f, "Request Smuggling"),
        }
    }
}

/// Detection rule
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u32,
    pub name: String,
    pub attack_type: AttackType,
    pub pattern: Regex,
    pub paranoia_level: u8,
    pub description: String,
}

/// Detection result
#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub rule_id: u32,
    pub rule_name: String,
    pub attack_type: AttackType,
    pub matched_value: String,
    pub location: String,
}

/// WAF configuration
#[derive(Debug, Clone)]
pub struct WafConfig {
    pub paranoia_level: u8,
    pub sqli_enabled: bool,
    pub xss_enabled: bool,
    pub path_traversal_enabled: bool,
    pub command_injection_enabled: bool,
    pub protocol_enabled: bool,
    pub block_mode: bool,
    pub exclude_paths: Vec<String>,
}

impl WafConfig {
    pub fn from_args(args: &Args) -> Self {
        let exclude_paths = args
            .exclude_paths
            .as_ref()
            .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        Self {
            paranoia_level: args.paranoia_level.clamp(1, 4),
            sqli_enabled: args.sqli,
            xss_enabled: args.xss,
            path_traversal_enabled: args.path_traversal,
            command_injection_enabled: args.command_injection,
            protocol_enabled: args.protocol,
            block_mode: args.block_mode,
            exclude_paths,
        }
    }
}

/// WAF engine
pub struct WafEngine {
    rules: Vec<Rule>,
    config: WafConfig,
}

impl WafEngine {
    pub fn new(config: WafConfig) -> Result<Self> {
        let rules = Self::build_rules(&config)?;
        info!(
            rules_count = rules.len(),
            paranoia_level = config.paranoia_level,
            "WAF engine initialized"
        );
        Ok(Self { rules, config })
    }

    fn build_rules(config: &WafConfig) -> Result<Vec<Rule>> {
        let mut rules = Vec::new();

        // SQL Injection rules
        if config.sqli_enabled {
            rules.extend(Self::sqli_rules(config.paranoia_level)?);
        }

        // XSS rules
        if config.xss_enabled {
            rules.extend(Self::xss_rules(config.paranoia_level)?);
        }

        // Path traversal rules
        if config.path_traversal_enabled {
            rules.extend(Self::path_traversal_rules(config.paranoia_level)?);
        }

        // Command injection rules
        if config.command_injection_enabled {
            rules.extend(Self::command_injection_rules(config.paranoia_level)?);
        }

        // Protocol attack rules
        if config.protocol_enabled {
            rules.extend(Self::protocol_rules(config.paranoia_level)?);
        }

        Ok(rules)
    }

    fn sqli_rules(paranoia_level: u8) -> Result<Vec<Rule>> {
        let mut rules = vec![
            // Level 1 - High confidence SQL injection
            Rule {
                id: 942100,
                name: "SQL Injection Attack Detected via libinjection".to_string(),
                attack_type: AttackType::SqlInjection,
                pattern: Regex::new(r"(?i)(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b.*\bWHERE\b)")?,
                paranoia_level: 1,
                description: "Detects UNION-based SQL injection".to_string(),
            },
            Rule {
                id: 942110,
                name: "SQL Injection Attack: Common Injection Testing".to_string(),
                attack_type: AttackType::SqlInjection,
                pattern: Regex::new(r"(?i)([\'\"];\s*(DROP|DELETE|UPDATE|INSERT|ALTER)\s)")?,
                paranoia_level: 1,
                description: "Detects destructive SQL commands".to_string(),
            },
            Rule {
                id: 942120,
                name: "SQL Injection Attack: SQL Operator Detected".to_string(),
                attack_type: AttackType::SqlInjection,
                pattern: Regex::new(r"(?i)(\bOR\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+|\bAND\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)")?,
                paranoia_level: 1,
                description: "Detects OR/AND-based SQL injection".to_string(),
            },
            Rule {
                id: 942130,
                name: "SQL Injection Attack: Tautology".to_string(),
                attack_type: AttackType::SqlInjection,
                pattern: Regex::new(r"(?i)([\'\"]?\s*OR\s*[\'\"]?1[\'\"]?\s*=\s*[\'\"]?1)")?,
                paranoia_level: 1,
                description: "Detects SQL tautology attacks".to_string(),
            },
            Rule {
                id: 942140,
                name: "SQL Injection Attack: SQL Comment Detected".to_string(),
                attack_type: AttackType::SqlInjection,
                pattern: Regex::new(r"(--|#|/\*.*\*/|;)")?,
                paranoia_level: 2,
                description: "Detects SQL comment injection".to_string(),
            },
        ];

        // Add more rules for higher paranoia levels
        if paranoia_level >= 2 {
            rules.push(Rule {
                id: 942200,
                name: "SQL Injection: MySQL Comment/Sleep".to_string(),
                attack_type: AttackType::SqlInjection,
                pattern: Regex::new(r"(?i)(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)")?,
                paranoia_level: 2,
                description: "Detects time-based SQL injection".to_string(),
            });
        }

        if paranoia_level >= 3 {
            rules.push(Rule {
                id: 942300,
                name: "SQL Injection: Hex Encoding".to_string(),
                attack_type: AttackType::SqlInjection,
                pattern: Regex::new(r"(?i)(0x[0-9a-f]{8,}|CHAR\s*\()")?,
                paranoia_level: 3,
                description: "Detects hex-encoded SQL injection".to_string(),
            });
        }

        Ok(rules.into_iter().filter(|r| r.paranoia_level <= paranoia_level).collect())
    }

    fn xss_rules(paranoia_level: u8) -> Result<Vec<Rule>> {
        let mut rules = vec![
            Rule {
                id: 941100,
                name: "XSS Attack Detected via libinjection".to_string(),
                attack_type: AttackType::Xss,
                pattern: Regex::new(r"(?i)(<script[^>]*>|</script>|javascript:|on\w+\s*=)")?,
                paranoia_level: 1,
                description: "Detects script tag XSS".to_string(),
            },
            Rule {
                id: 941110,
                name: "XSS Filter - Category 1: Script Tag Vector".to_string(),
                attack_type: AttackType::Xss,
                pattern: Regex::new(r"(?i)(<script|<iframe|<object|<embed|<applet)")?,
                paranoia_level: 1,
                description: "Detects dangerous HTML tags".to_string(),
            },
            Rule {
                id: 941120,
                name: "XSS Filter - Category 2: Event Handler Vector".to_string(),
                attack_type: AttackType::Xss,
                pattern: Regex::new(r"(?i)(onerror|onload|onclick|onmouseover|onfocus|onblur)\s*=")?,
                paranoia_level: 1,
                description: "Detects event handler XSS".to_string(),
            },
            Rule {
                id: 941130,
                name: "XSS Filter - Category 3: Attribute Vector".to_string(),
                attack_type: AttackType::Xss,
                pattern: Regex::new(r"(?i)(src|href|data)\s*=\s*[\"']?javascript:")?,
                paranoia_level: 1,
                description: "Detects javascript: protocol XSS".to_string(),
            },
            Rule {
                id: 941140,
                name: "XSS Filter - Category 4: Data URI".to_string(),
                attack_type: AttackType::Xss,
                pattern: Regex::new(r"(?i)data:\s*text/html")?,
                paranoia_level: 2,
                description: "Detects data URI XSS".to_string(),
            },
        ];

        if paranoia_level >= 2 {
            rules.push(Rule {
                id: 941200,
                name: "XSS using expression()".to_string(),
                attack_type: AttackType::Xss,
                pattern: Regex::new(r"(?i)(expression\s*\(|behavior\s*:|binding\s*:)")?,
                paranoia_level: 2,
                description: "Detects CSS expression XSS".to_string(),
            });
        }

        Ok(rules.into_iter().filter(|r| r.paranoia_level <= paranoia_level).collect())
    }

    fn path_traversal_rules(paranoia_level: u8) -> Result<Vec<Rule>> {
        let rules = vec![
            Rule {
                id: 930100,
                name: "Path Traversal Attack (/../)".to_string(),
                attack_type: AttackType::PathTraversal,
                pattern: Regex::new(r"(\.{2,}/|\.{2,}\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./)")?,
                paranoia_level: 1,
                description: "Detects path traversal attempts".to_string(),
            },
            Rule {
                id: 930110,
                name: "Path Traversal Attack (encoded)".to_string(),
                attack_type: AttackType::PathTraversal,
                pattern: Regex::new(r"(?i)(%c0%ae|%c1%9c|%252e)")?,
                paranoia_level: 1,
                description: "Detects encoded path traversal".to_string(),
            },
            Rule {
                id: 930120,
                name: "OS File Access Attempt".to_string(),
                attack_type: AttackType::PathTraversal,
                pattern: Regex::new(r"(?i)(/etc/passwd|/etc/shadow|/proc/|c:\\windows|c:\\winnt)")?,
                paranoia_level: 1,
                description: "Detects OS file access".to_string(),
            },
        ];

        Ok(rules.into_iter().filter(|r| r.paranoia_level <= paranoia_level).collect())
    }

    fn command_injection_rules(paranoia_level: u8) -> Result<Vec<Rule>> {
        let rules = vec![
            Rule {
                id: 932100,
                name: "Remote Command Execution".to_string(),
                attack_type: AttackType::CommandInjection,
                pattern: Regex::new(r"(?i)(\|\s*\w+|;\s*(ls|cat|whoami|id|pwd)|`[^`]+`)")?,
                paranoia_level: 1,
                description: "Detects command injection via pipe/semicolon".to_string(),
            },
            Rule {
                id: 932110,
                name: "Command Injection: Unix Command".to_string(),
                attack_type: AttackType::CommandInjection,
                pattern: Regex::new(r"(?i)(\$\(|&&\s*(wget|curl|nc|bash|sh)|/bin/(sh|bash))")?,
                paranoia_level: 1,
                description: "Detects Unix command injection".to_string(),
            },
            Rule {
                id: 932120,
                name: "Command Injection: Windows Command".to_string(),
                attack_type: AttackType::CommandInjection,
                pattern: Regex::new(r"(?i)(cmd\.exe|powershell|net\s+user)")?,
                paranoia_level: 1,
                description: "Detects Windows command injection".to_string(),
            },
        ];

        Ok(rules.into_iter().filter(|r| r.paranoia_level <= paranoia_level).collect())
    }

    fn protocol_rules(paranoia_level: u8) -> Result<Vec<Rule>> {
        let rules = vec![
            Rule {
                id: 920100,
                name: "Invalid HTTP Request Line".to_string(),
                attack_type: AttackType::ProtocolAttack,
                pattern: Regex::new(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")?,
                paranoia_level: 1,
                description: "Detects control characters in request".to_string(),
            },
            Rule {
                id: 920170,
                name: "GET/HEAD Request with Body".to_string(),
                attack_type: AttackType::RequestSmuggling,
                pattern: Regex::new(r"(?i)^(GET|HEAD)\s.*content-length:\s*[1-9]")?,
                paranoia_level: 2,
                description: "Detects GET/HEAD with body".to_string(),
            },
            Rule {
                id: 913100,
                name: "Scanner Detection".to_string(),
                attack_type: AttackType::ScannerDetection,
                pattern: Regex::new(r"(?i)(nikto|sqlmap|nessus|acunetix|nmap|masscan)")?,
                paranoia_level: 1,
                description: "Detects known scanner user agents".to_string(),
            },
        ];

        Ok(rules.into_iter().filter(|r| r.paranoia_level <= paranoia_level).collect())
    }

    /// Check a value against all rules
    pub fn check(&self, value: &str, location: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for rule in &self.rules {
            if rule.pattern.is_match(value) {
                let matched = rule.pattern.find(value).map(|m| m.as_str().to_string()).unwrap_or_default();
                detections.push(Detection {
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                    attack_type: rule.attack_type,
                    matched_value: matched,
                    location: location.to_string(),
                });
            }
        }

        detections
    }

    /// Check entire request
    pub fn check_request(&self, path: &str, query: Option<&str>, headers: &[(String, String)]) -> Vec<Detection> {
        let mut all_detections = Vec::new();

        // Check path
        all_detections.extend(self.check(path, "path"));

        // Check query string
        if let Some(q) = query {
            all_detections.extend(self.check(q, "query"));
        }

        // Check headers
        for (name, value) in headers {
            let location = format!("header:{}", name);
            all_detections.extend(self.check(value, &location));
        }

        all_detections
    }

    /// Check if path should be excluded
    pub fn is_excluded(&self, path: &str) -> bool {
        self.config.exclude_paths.iter().any(|p| path.starts_with(p))
    }
}

/// WAF agent
pub struct WafAgent {
    engine: WafEngine,
}

impl WafAgent {
    pub fn new(config: WafConfig) -> Result<Self> {
        let engine = WafEngine::new(config)?;
        Ok(Self { engine })
    }
}

#[async_trait::async_trait]
impl AgentHandler for WafAgent {
    async fn on_request_headers(
        &self,
        event: RequestHeadersEvent,
    ) -> AgentResult<(Decision, Mutations)> {
        let path = event.path.as_deref().unwrap_or("/");

        // Check exclusions
        if self.engine.is_excluded(path) {
            debug!(path = path, "Path excluded from WAF");
            return Ok((Decision::Allow, Mutations::default()));
        }

        // Extract query string from path
        let (path_only, query) = path.split_once('?').map(|(p, q)| (p, Some(q))).unwrap_or((path, None));

        // Check request
        let detections = self.engine.check_request(path_only, query, &event.headers);

        if detections.is_empty() {
            return Ok((Decision::Allow, Mutations::default()));
        }

        // Log detections
        for detection in &detections {
            warn!(
                rule_id = detection.rule_id,
                rule_name = %detection.rule_name,
                attack_type = %detection.attack_type,
                location = %detection.location,
                matched = %detection.matched_value,
                "WAF detection"
            );
        }

        let mut mutations = Mutations::default();

        // Add detection headers
        mutations.response_headers.push((
            "X-WAF-Blocked".to_string(),
            "true".to_string(),
        ));
        mutations.response_headers.push((
            "X-WAF-Rule".to_string(),
            detections.first().map(|d| d.rule_id.to_string()).unwrap_or_default(),
        ));

        if self.engine.config.block_mode {
            info!(
                detections = detections.len(),
                first_rule = detections.first().map(|d| d.rule_id).unwrap_or(0),
                "Request blocked by WAF"
            );
            Ok((Decision::Block { status_code: 403 }, mutations))
        } else {
            info!(
                detections = detections.len(),
                "WAF detections (detect-only mode)"
            );
            // In detect-only mode, add headers but allow request
            mutations.request_headers.push((
                "X-WAF-Detected".to_string(),
                detections.iter().map(|d| d.rule_id.to_string()).collect::<Vec<_>>().join(","),
            ));
            Ok((Decision::Allow, mutations))
        }
    }

    async fn on_response_headers(
        &self,
        _event: ResponseHeadersEvent,
    ) -> AgentResult<(Decision, Mutations)> {
        Ok((Decision::Allow, Mutations::default()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("{}={},sentinel_agent_protocol=info", env!("CARGO_CRATE_NAME"), log_level))
        .json()
        .init();

    info!("Starting Sentinel WAF Agent");

    // Build configuration
    let config = WafConfig::from_args(&args);

    info!(
        paranoia_level = config.paranoia_level,
        sqli = config.sqli_enabled,
        xss = config.xss_enabled,
        path_traversal = config.path_traversal_enabled,
        command_injection = config.command_injection_enabled,
        block_mode = config.block_mode,
        "Configuration loaded"
    );

    // Create agent
    let agent = WafAgent::new(config)?;

    // Remove existing socket if present
    if args.socket.exists() {
        std::fs::remove_file(&args.socket)?;
    }

    // Start agent server
    info!(socket = ?args.socket, "Starting agent server");
    let server = AgentServer::new(agent);
    server.serve_unix(&args.socket).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> WafEngine {
        let config = WafConfig {
            paranoia_level: 2,
            sqli_enabled: true,
            xss_enabled: true,
            path_traversal_enabled: true,
            command_injection_enabled: true,
            protocol_enabled: true,
            block_mode: true,
            exclude_paths: vec!["/health".to_string()],
        };
        WafEngine::new(config).unwrap()
    }

    #[test]
    fn test_sqli_detection() {
        let engine = test_engine();

        // Should detect
        let detections = engine.check("' OR '1'='1", "query");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].attack_type, AttackType::SqlInjection);

        let detections = engine.check("1; DROP TABLE users;--", "query");
        assert!(!detections.is_empty());

        let detections = engine.check("UNION SELECT * FROM users", "query");
        assert!(!detections.is_empty());

        // Should not detect
        let detections = engine.check("normal query string", "query");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_xss_detection() {
        let engine = test_engine();

        // Should detect
        let detections = engine.check("<script>alert('xss')</script>", "param");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].attack_type, AttackType::Xss);

        let detections = engine.check("onclick=alert(1)", "param");
        assert!(!detections.is_empty());

        let detections = engine.check("javascript:alert(1)", "param");
        assert!(!detections.is_empty());

        // Should not detect
        let detections = engine.check("normal text content", "param");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_path_traversal_detection() {
        let engine = test_engine();

        // Should detect
        let detections = engine.check("../../../etc/passwd", "path");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].attack_type, AttackType::PathTraversal);

        let detections = engine.check("%2e%2e%2f", "path");
        assert!(!detections.is_empty());

        // Should not detect
        let detections = engine.check("/api/users/123", "path");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_command_injection_detection() {
        let engine = test_engine();

        // Should detect
        let detections = engine.check("| cat /etc/passwd", "param");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].attack_type, AttackType::CommandInjection);

        let detections = engine.check("; whoami", "param");
        assert!(!detections.is_empty());

        // Should not detect
        let detections = engine.check("normal parameter", "param");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_exclusion() {
        let engine = test_engine();

        assert!(engine.is_excluded("/health"));
        assert!(engine.is_excluded("/health/live"));
        assert!(!engine.is_excluded("/api/users"));
    }

    #[test]
    fn test_full_request() {
        let engine = test_engine();

        let headers = vec![
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        // Clean request
        let detections = engine.check_request("/api/users", Some("id=123"), &headers);
        assert!(detections.is_empty());

        // Malicious query
        let detections = engine.check_request("/api/users", Some("id=1' OR '1'='1"), &headers);
        assert!(!detections.is_empty());
    }
}
