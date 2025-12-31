//! Sentinel WAF Agent
//!
//! A Web Application Firewall agent for Sentinel proxy that detects and blocks
//! common web attacks including SQL injection, XSS, path traversal, and more.

use anyhow::Result;
use base64::Engine;
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AgentServer, AuditMetadata, HeaderOp, RequestBodyChunkEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent,
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

    /// Enable request body inspection
    #[arg(long, default_value = "true", env = "WAF_BODY_INSPECTION")]
    body_inspection: bool,

    /// Maximum body size to inspect in bytes (default 1MB)
    #[arg(long, default_value = "1048576", env = "WAF_MAX_BODY_SIZE")]
    max_body_size: usize,

    /// Enable response body inspection (detect attacks in server responses)
    #[arg(long, default_value = "false", env = "WAF_RESPONSE_INSPECTION")]
    response_inspection: bool,

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
    pub body_inspection_enabled: bool,
    pub max_body_size: usize,
    pub response_inspection_enabled: bool,
}

impl WafConfig {
    fn from_args(args: &Args) -> Self {
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
            body_inspection_enabled: args.body_inspection,
            max_body_size: args.max_body_size,
            response_inspection_enabled: args.response_inspection,
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
                pattern: Regex::new(
                    r"(?i)(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b.*\bWHERE\b)",
                )?,
                paranoia_level: 1,
                description: "Detects UNION-based SQL injection".to_string(),
            },
            Rule {
                id: 942110,
                name: "SQL Injection Attack: Common Injection Testing".to_string(),
                attack_type: AttackType::SqlInjection,
                pattern: Regex::new(r#"(?i)(['"];\s*(DROP|DELETE|UPDATE|INSERT|ALTER)\s)"#)?,
                paranoia_level: 1,
                description: "Detects destructive SQL commands".to_string(),
            },
            Rule {
                id: 942120,
                name: "SQL Injection Attack: SQL Operator Detected".to_string(),
                attack_type: AttackType::SqlInjection,
                pattern: Regex::new(
                    r#"(?i)(\bOR\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+|\bAND\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+)"#,
                )?,
                paranoia_level: 1,
                description: "Detects OR/AND-based SQL injection".to_string(),
            },
            Rule {
                id: 942130,
                name: "SQL Injection Attack: Tautology".to_string(),
                attack_type: AttackType::SqlInjection,
                pattern: Regex::new(r#"(?i)(['"]?\s*OR\s*['"]?1['"]?\s*=\s*['"]?1)"#)?,
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

        Ok(rules
            .into_iter()
            .filter(|r| r.paranoia_level <= paranoia_level)
            .collect())
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
                pattern: Regex::new(
                    r"(?i)(onerror|onload|onclick|onmouseover|onfocus|onblur)\s*=",
                )?,
                paranoia_level: 1,
                description: "Detects event handler XSS".to_string(),
            },
            Rule {
                id: 941130,
                name: "XSS Filter - Category 3: Attribute Vector".to_string(),
                attack_type: AttackType::Xss,
                pattern: Regex::new(r#"(?i)(src|href|data)\s*=\s*["']?javascript:"#)?,
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

        Ok(rules
            .into_iter()
            .filter(|r| r.paranoia_level <= paranoia_level)
            .collect())
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

        Ok(rules
            .into_iter()
            .filter(|r| r.paranoia_level <= paranoia_level)
            .collect())
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

        Ok(rules
            .into_iter()
            .filter(|r| r.paranoia_level <= paranoia_level)
            .collect())
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

        Ok(rules
            .into_iter()
            .filter(|r| r.paranoia_level <= paranoia_level)
            .collect())
    }

    /// Check a value against all rules
    pub fn check(&self, value: &str, location: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for rule in &self.rules {
            if rule.pattern.is_match(value) {
                let matched = rule
                    .pattern
                    .find(value)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
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
    pub fn check_request(
        &self,
        path: &str,
        query: Option<&str>,
        headers: &HashMap<String, Vec<String>>,
    ) -> Vec<Detection> {
        let mut all_detections = Vec::new();

        // Check path
        all_detections.extend(self.check(path, "path"));

        // Check query string
        if let Some(q) = query {
            all_detections.extend(self.check(q, "query"));
        }

        // Check headers
        for (name, values) in headers {
            let location = format!("header:{}", name);
            for value in values {
                all_detections.extend(self.check(value, &location));
            }
        }

        all_detections
    }

    /// Check if path should be excluded
    pub fn is_excluded(&self, path: &str) -> bool {
        self.config
            .exclude_paths
            .iter()
            .any(|p| path.starts_with(p))
    }
}

/// Body accumulator for tracking in-progress bodies
#[derive(Debug, Default)]
struct BodyAccumulator {
    data: Vec<u8>,
}

/// WAF agent
pub struct WafAgent {
    engine: WafEngine,
    pending_request_bodies: Arc<RwLock<HashMap<String, BodyAccumulator>>>,
    pending_response_bodies: Arc<RwLock<HashMap<String, BodyAccumulator>>>,
}

impl WafAgent {
    pub fn new(config: WafConfig) -> Result<Self> {
        let engine = WafEngine::new(config)?;
        Ok(Self {
            engine,
            pending_request_bodies: Arc::new(RwLock::new(HashMap::new())),
            pending_response_bodies: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[async_trait::async_trait]
impl AgentHandler for WafAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let path = &event.uri;

        // Check exclusions
        if self.engine.is_excluded(path) {
            debug!(path = path, "Path excluded from WAF");
            return AgentResponse::default_allow();
        }

        // Extract query string from path
        let (path_only, query) = path
            .split_once('?')
            .map(|(p, q)| (p, Some(q)))
            .unwrap_or((path, None));

        // Check request
        let detections = self.engine.check_request(path_only, query, &event.headers);

        if detections.is_empty() {
            return AgentResponse::default_allow();
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

        let rule_ids: Vec<String> = detections.iter().map(|d| d.rule_id.to_string()).collect();

        if self.engine.config.block_mode {
            info!(
                detections = detections.len(),
                first_rule = detections.first().map(|d| d.rule_id).unwrap_or(0),
                "Request blocked by WAF"
            );
            AgentResponse::block(403, Some("Forbidden".to_string()))
                .add_response_header(HeaderOp::Set {
                    name: "X-WAF-Blocked".to_string(),
                    value: "true".to_string(),
                })
                .add_response_header(HeaderOp::Set {
                    name: "X-WAF-Rule".to_string(),
                    value: rule_ids.first().cloned().unwrap_or_default(),
                })
                .with_audit(AuditMetadata {
                    tags: vec!["waf".to_string(), "blocked".to_string()],
                    rule_ids: rule_ids.clone(),
                    ..Default::default()
                })
        } else {
            info!(
                detections = detections.len(),
                "WAF detections (detect-only mode)"
            );
            // In detect-only mode, add headers but allow request
            AgentResponse::default_allow()
                .add_request_header(HeaderOp::Set {
                    name: "X-WAF-Detected".to_string(),
                    value: rule_ids.join(","),
                })
                .with_audit(AuditMetadata {
                    tags: vec!["waf".to_string(), "detected".to_string()],
                    rule_ids,
                    ..Default::default()
                })
        }
    }

    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        // Skip if body inspection is disabled
        if !self.engine.config.body_inspection_enabled {
            return AgentResponse::default_allow();
        }

        // Decode base64 chunk
        let chunk = match base64::engine::general_purpose::STANDARD.decode(&event.data) {
            Ok(data) => data,
            Err(e) => {
                warn!(error = %e, "Failed to decode body chunk");
                return AgentResponse::default_allow();
            }
        };

        // Accumulate chunk
        let mut pending = self.pending_request_bodies.write().await;
        let accumulator = pending
            .entry(event.correlation_id.clone())
            .or_insert_with(BodyAccumulator::default);

        // Check size limit before accumulating
        if accumulator.data.len() + chunk.len() > self.engine.config.max_body_size {
            debug!(
                correlation_id = %event.correlation_id,
                current_size = accumulator.data.len(),
                chunk_size = chunk.len(),
                max_size = self.engine.config.max_body_size,
                "Body exceeds max size, skipping inspection"
            );
            pending.remove(&event.correlation_id);
            return AgentResponse::default_allow();
        }

        accumulator.data.extend(chunk);

        // If this is the last chunk, inspect the full body
        if event.is_last {
            let body_data = pending.remove(&event.correlation_id).unwrap();
            let body_str = String::from_utf8_lossy(&body_data.data);

            debug!(
                correlation_id = %event.correlation_id,
                body_size = body_data.data.len(),
                "Inspecting request body"
            );

            let detections = self.engine.check(&body_str, "body");

            if detections.is_empty() {
                return AgentResponse::default_allow();
            }

            // Log detections
            for detection in &detections {
                warn!(
                    rule_id = detection.rule_id,
                    rule_name = %detection.rule_name,
                    attack_type = %detection.attack_type,
                    location = %detection.location,
                    matched = %detection.matched_value,
                    "WAF detection in body"
                );
            }

            let rule_ids: Vec<String> = detections.iter().map(|d| d.rule_id.to_string()).collect();

            if self.engine.config.block_mode {
                info!(
                    detections = detections.len(),
                    first_rule = detections.first().map(|d| d.rule_id).unwrap_or(0),
                    "Request blocked by WAF (body inspection)"
                );
                return AgentResponse::block(403, Some("Forbidden".to_string()))
                    .add_response_header(HeaderOp::Set {
                        name: "X-WAF-Blocked".to_string(),
                        value: "true".to_string(),
                    })
                    .add_response_header(HeaderOp::Set {
                        name: "X-WAF-Rule".to_string(),
                        value: rule_ids.first().cloned().unwrap_or_default(),
                    })
                    .with_audit(AuditMetadata {
                        tags: vec!["waf".to_string(), "blocked".to_string(), "body".to_string()],
                        rule_ids: rule_ids.clone(),
                        ..Default::default()
                    });
            } else {
                info!(
                    detections = detections.len(),
                    "WAF detections in body (detect-only mode)"
                );
                return AgentResponse::default_allow()
                    .add_request_header(HeaderOp::Set {
                        name: "X-WAF-Detected".to_string(),
                        value: rule_ids.join(","),
                    })
                    .with_audit(AuditMetadata {
                        tags: vec![
                            "waf".to_string(),
                            "detected".to_string(),
                            "body".to_string(),
                        ],
                        rule_ids,
                        ..Default::default()
                    });
            }
        }

        AgentResponse::default_allow()
    }

    async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse {
        // Skip if response inspection is disabled
        if !self.engine.config.response_inspection_enabled {
            return AgentResponse::default_allow();
        }

        // Decode base64 chunk
        let chunk = match base64::engine::general_purpose::STANDARD.decode(&event.data) {
            Ok(data) => data,
            Err(e) => {
                warn!(error = %e, "Failed to decode response body chunk");
                return AgentResponse::default_allow();
            }
        };

        // Accumulate chunk
        let mut pending = self.pending_response_bodies.write().await;
        let accumulator = pending
            .entry(event.correlation_id.clone())
            .or_insert_with(BodyAccumulator::default);

        // Check size limit before accumulating
        if accumulator.data.len() + chunk.len() > self.engine.config.max_body_size {
            debug!(
                correlation_id = %event.correlation_id,
                current_size = accumulator.data.len(),
                chunk_size = chunk.len(),
                max_size = self.engine.config.max_body_size,
                "Response body exceeds max size, skipping inspection"
            );
            pending.remove(&event.correlation_id);
            return AgentResponse::default_allow();
        }

        accumulator.data.extend(chunk);

        // If this is the last chunk, inspect the full body
        if event.is_last {
            let body_data = pending.remove(&event.correlation_id).unwrap();
            let body_str = String::from_utf8_lossy(&body_data.data);

            debug!(
                correlation_id = %event.correlation_id,
                body_size = body_data.data.len(),
                "Inspecting response body"
            );

            let detections = self.engine.check(&body_str, "response_body");

            if detections.is_empty() {
                return AgentResponse::default_allow();
            }

            // Log detections
            for detection in &detections {
                warn!(
                    rule_id = detection.rule_id,
                    rule_name = %detection.rule_name,
                    attack_type = %detection.attack_type,
                    location = %detection.location,
                    matched = %detection.matched_value,
                    "WAF detection in response body"
                );
            }

            let rule_ids: Vec<String> = detections.iter().map(|d| d.rule_id.to_string()).collect();

            // For response bodies, we can only log/audit - blocking would require
            // dropping the response which may not be desirable. We add headers to
            // indicate detection.
            info!(
                detections = detections.len(),
                first_rule = detections.first().map(|d| d.rule_id).unwrap_or(0),
                "WAF detection in response (logged)"
            );

            return AgentResponse::default_allow()
                .add_response_header(HeaderOp::Set {
                    name: "X-WAF-Response-Detected".to_string(),
                    value: rule_ids.join(","),
                })
                .with_audit(AuditMetadata {
                    tags: vec![
                        "waf".to_string(),
                        "detected".to_string(),
                        "response_body".to_string(),
                    ],
                    rule_ids,
                    ..Default::default()
                });
        }

        AgentResponse::default_allow()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!(
            "{}={},sentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
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
        body_inspection = config.body_inspection_enabled,
        response_inspection = config.response_inspection_enabled,
        max_body_size = config.max_body_size,
        "Configuration loaded"
    );

    // Create agent
    let agent = WafAgent::new(config)?;

    // Start agent server
    info!(socket = ?args.socket, "Starting agent server");
    let server = AgentServer::new("sentinel-waf-agent", args.socket, Box::new(agent));
    server.run().await.map_err(|e| anyhow::anyhow!("{}", e))?;

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
            body_inspection_enabled: true,
            max_body_size: 1048576, // 1MB
            response_inspection_enabled: true,
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

        // Should detect - use backticks command substitution
        let detections = engine.check("`whoami`", "param");
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

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), vec!["Mozilla/5.0".to_string()]);
        headers.insert(
            "Content-Type".to_string(),
            vec!["application/json".to_string()],
        );

        // Clean request
        let detections = engine.check_request("/api/users", Some("id=123"), &headers);
        assert!(detections.is_empty());

        // Malicious query
        let detections = engine.check_request("/api/users", Some("id=1' OR '1'='1"), &headers);
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_body_sqli_detection() {
        let engine = test_engine();

        // JSON body with SQL injection
        let body = r#"{"username": "admin", "password": "' OR '1'='1"}"#;
        let detections = engine.check(body, "body");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].attack_type, AttackType::SqlInjection);

        // Form data with SQL injection
        let body = "username=admin&password=' OR '1'='1";
        let detections = engine.check(body, "body");
        assert!(!detections.is_empty());

        // Clean body
        let body = r#"{"username": "john", "email": "john@example.com"}"#;
        let detections = engine.check(body, "body");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_body_xss_detection() {
        let engine = test_engine();

        // JSON body with XSS
        let body = r#"{"comment": "<script>alert('xss')</script>"}"#;
        let detections = engine.check(body, "body");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].attack_type, AttackType::Xss);

        // Form data with XSS
        let body = "comment=<script>alert(1)</script>";
        let detections = engine.check(body, "body");
        assert!(!detections.is_empty());

        // Clean body
        let body = r#"{"comment": "This is a normal comment"}"#;
        let detections = engine.check(body, "body");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_body_command_injection_detection() {
        let engine = test_engine();

        // JSON body with command injection using backticks
        let body = r#"{"filename": "`whoami`"}"#;
        let detections = engine.check(body, "body");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].attack_type, AttackType::CommandInjection);

        // JSON body with command injection using $()
        let body = r#"{"cmd": "$(cat /etc/passwd)"}"#;
        let detections = engine.check(body, "body");
        assert!(!detections.is_empty());
        assert!(detections
            .iter()
            .any(|d| d.attack_type == AttackType::CommandInjection));

        // Clean body
        let body = r#"{"filename": "document.pdf"}"#;
        let detections = engine.check(body, "body");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_body_inspection_config() {
        // Test with body inspection disabled
        let config = WafConfig {
            paranoia_level: 2,
            sqli_enabled: true,
            xss_enabled: true,
            path_traversal_enabled: true,
            command_injection_enabled: true,
            protocol_enabled: true,
            block_mode: true,
            exclude_paths: vec![],
            body_inspection_enabled: false,
            max_body_size: 1024,
            response_inspection_enabled: false,
        };
        let engine = WafEngine::new(config).unwrap();

        // Engine still works for checking, the disabled flag is used by WafAgent
        let body = r#"{"password": "' OR '1'='1"}"#;
        let detections = engine.check(body, "body");
        assert!(!detections.is_empty()); // Engine still detects, agent would skip
    }

    #[test]
    fn test_response_body_xss_detection() {
        let engine = test_engine();

        // Response containing reflected XSS
        let response = r#"<html><body>Welcome <script>alert('xss')</script></body></html>"#;
        let detections = engine.check(response, "response_body");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].attack_type, AttackType::Xss);

        // Response with event handler XSS
        let response = r#"<div onclick=alert(1)>Click me</div>"#;
        let detections = engine.check(response, "response_body");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].attack_type, AttackType::Xss);

        // Clean response
        let response = r#"{"status": "ok", "message": "User created successfully"}"#;
        let detections = engine.check(response, "response_body");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_response_body_error_leakage() {
        let engine = test_engine();

        // Response leaking path traversal in error
        let response = "File not found: /etc/passwd";
        let detections = engine.check(response, "response_body");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].attack_type, AttackType::PathTraversal);

        // Response leaking command output
        let response = "Error executing: /bin/bash -c 'whoami'";
        let detections = engine.check(response, "response_body");
        assert!(!detections.is_empty());
    }
}
