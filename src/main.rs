//! Sentinel WAF Agent CLI
//!
//! Command-line interface for the Web Application Firewall agent.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use sentinel_agent_protocol::AgentServer;
use sentinel_agent_waf::{WafAgent, WafConfig};

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

impl Args {
    fn to_config(&self) -> WafConfig {
        let exclude_paths = self
            .exclude_paths
            .as_ref()
            .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        WafConfig {
            paranoia_level: self.paranoia_level.clamp(1, 4),
            sqli_enabled: self.sqli,
            xss_enabled: self.xss,
            path_traversal_enabled: self.path_traversal,
            command_injection_enabled: self.command_injection,
            protocol_enabled: self.protocol,
            block_mode: self.block_mode,
            exclude_paths,
            body_inspection_enabled: self.body_inspection,
            max_body_size: self.max_body_size,
            response_inspection_enabled: self.response_inspection,
        }
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
    let config = args.to_config();

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
