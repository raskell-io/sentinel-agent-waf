//! WAF Configuration Types
//!
//! Configuration for the WAF engine including scoring thresholds,
//! rule management, and exclusions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;


/// WAF configuration
#[derive(Debug, Clone)]
pub struct WafConfig {
    /// Paranoia level (1-4)
    pub paranoia_level: u8,
    /// Enable SQL injection detection
    pub sqli_enabled: bool,
    /// Enable XSS detection
    pub xss_enabled: bool,
    /// Enable path traversal detection
    pub path_traversal_enabled: bool,
    /// Enable command injection detection
    pub command_injection_enabled: bool,
    /// Enable protocol attack detection
    pub protocol_enabled: bool,
    /// Block mode (true) or detect-only (false)
    pub block_mode: bool,
    /// Paths to exclude from inspection
    pub exclude_paths: Vec<String>,
    /// Enable request body inspection
    pub body_inspection_enabled: bool,
    /// Maximum body size to inspect
    pub max_body_size: usize,
    /// Enable response body inspection
    pub response_inspection_enabled: bool,
    /// Scoring configuration
    pub scoring: ScoringConfig,
    /// Rule management configuration
    pub rules: RuleManagement,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            paranoia_level: 1,
            sqli_enabled: true,
            xss_enabled: true,
            path_traversal_enabled: true,
            command_injection_enabled: true,
            protocol_enabled: true,
            block_mode: true,
            exclude_paths: vec![],
            body_inspection_enabled: true,
            max_body_size: 1048576, // 1MB
            response_inspection_enabled: false,
            scoring: ScoringConfig::default(),
            rules: RuleManagement::default(),
        }
    }
}

/// Scoring configuration for anomaly-based detection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ScoringConfig {
    /// Enable scoring mode (vs binary block/allow)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Score threshold for blocking (default: 25)
    #[serde(default = "default_block_threshold")]
    pub block_threshold: u32,
    /// Score threshold for logging (default: 10)
    #[serde(default = "default_log_threshold")]
    pub log_threshold: u32,
    /// Per-category score multipliers
    #[serde(default)]
    pub category_weights: HashMap<String, f32>,
    /// Location-based score multipliers
    #[serde(default)]
    pub location_weights: LocationWeights,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_threshold: 25,
            log_threshold: 10,
            category_weights: HashMap::new(),
            location_weights: LocationWeights::default(),
        }
    }
}

/// Location-based score multipliers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LocationWeights {
    /// Path multiplier
    #[serde(default = "default_path_weight")]
    pub path: f32,
    /// Query string multiplier (highest risk)
    #[serde(default = "default_query_weight")]
    pub query: f32,
    /// Header multiplier
    #[serde(default = "default_header_weight")]
    pub header: f32,
    /// Cookie multiplier
    #[serde(default = "default_cookie_weight")]
    pub cookie: f32,
    /// Body multiplier
    #[serde(default = "default_body_weight")]
    pub body: f32,
}

impl Default for LocationWeights {
    fn default() -> Self {
        Self {
            path: 1.2,
            query: 1.5,
            header: 1.0,
            cookie: 1.3,
            body: 1.2,
        }
    }
}

impl LocationWeights {
    /// Get weight for a location string
    pub fn get(&self, location: &str) -> f32 {
        if location == "path" {
            self.path
        } else if location == "query" {
            self.query
        } else if location.starts_with("header:") {
            self.header
        } else if location.starts_with("cookie:") {
            self.cookie
        } else if location == "body" || location == "response_body" {
            self.body
        } else {
            1.0
        }
    }
}

/// Rule management configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleManagement {
    /// Explicitly enabled rules (if set, only these run)
    #[serde(default)]
    pub enabled: Option<Vec<RuleSelector>>,
    /// Explicitly disabled rules
    #[serde(default)]
    pub disabled: Vec<RuleSelector>,
    /// Per-rule overrides
    #[serde(default)]
    pub overrides: Vec<RuleOverride>,
    /// Exclusions (skip rules for certain conditions)
    #[serde(default)]
    pub exclusions: Vec<RuleExclusion>,
}

/// Rule selector for enabling/disabling rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleSelector {
    /// Single rule by ID: 942100
    Id(u32),
    /// Pattern: "942*", "942100-942199", "@sqli-union"
    Pattern(String),
}

impl RuleSelector {
    /// Check if this selector matches a rule
    pub fn matches(&self, rule_id: u32, tags: &[String]) -> bool {
        match self {
            RuleSelector::Id(id) => *id == rule_id,
            RuleSelector::Pattern(pattern) => {
                // Tag match: @tag-name
                if let Some(tag) = pattern.strip_prefix('@') {
                    return tags.iter().any(|t| t == tag);
                }

                // Range match: 942100-942199
                if let Some((start, end)) = pattern.split_once('-') {
                    if let (Ok(start_id), Ok(end_id)) = (start.parse::<u32>(), end.parse::<u32>()) {
                        return rule_id >= start_id && rule_id <= end_id;
                    }
                }

                // Wildcard match: 942*
                if let Some(prefix) = pattern.strip_suffix('*') {
                    let rule_str = rule_id.to_string();
                    return rule_str.starts_with(prefix);
                }

                // Exact match as string
                pattern == &rule_id.to_string()
            }
        }
    }
}

/// Rule override configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleOverride {
    /// Rules to override
    pub rules: Vec<RuleSelector>,
    /// Override action
    #[serde(default)]
    pub action: Option<OverrideAction>,
    /// Override base score
    #[serde(default)]
    pub score: Option<u32>,
    /// Conditions for this override
    #[serde(default)]
    pub conditions: Option<ExclusionConditions>,
}

/// Override action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OverrideAction {
    /// Block on match
    Block,
    /// Log only
    Log,
    /// Allow (skip rule)
    Allow,
}

/// Rule exclusion configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleExclusion {
    /// Rules to exclude
    pub rules: Vec<RuleSelector>,
    /// Conditions for exclusion
    pub conditions: ExclusionConditions,
}

/// Conditions for rule exclusions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExclusionConditions {
    /// Path prefixes
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    /// Path regex pattern
    #[serde(default)]
    pub path_regex: Option<String>,
    /// Source IP/CIDR ranges
    #[serde(default)]
    pub source_ips: Option<Vec<String>>,
    /// Header matches
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    /// HTTP methods
    #[serde(default)]
    pub methods: Option<Vec<String>>,
}

/// JSON-serializable config for Configure events
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WafConfigJson {
    #[serde(default = "default_paranoia")]
    pub paranoia_level: u8,
    #[serde(default = "default_true")]
    pub sqli: bool,
    #[serde(default = "default_true")]
    pub xss: bool,
    #[serde(default = "default_true")]
    pub path_traversal: bool,
    #[serde(default = "default_true")]
    pub command_injection: bool,
    #[serde(default = "default_true")]
    pub protocol: bool,
    #[serde(default = "default_true")]
    pub block_mode: bool,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    #[serde(default = "default_true")]
    pub body_inspection: bool,
    #[serde(default = "default_max_body")]
    pub max_body_size: usize,
    #[serde(default)]
    pub response_inspection: bool,
    #[serde(default)]
    pub scoring: Option<ScoringConfig>,
    #[serde(default)]
    pub rules: Option<RuleManagement>,
}

fn default_paranoia() -> u8 {
    1
}

fn default_true() -> bool {
    true
}

fn default_max_body() -> usize {
    1048576
}

fn default_block_threshold() -> u32 {
    25
}

fn default_log_threshold() -> u32 {
    10
}

fn default_path_weight() -> f32 {
    1.2
}

fn default_query_weight() -> f32 {
    1.5
}

fn default_header_weight() -> f32 {
    1.0
}

fn default_cookie_weight() -> f32 {
    1.3
}

fn default_body_weight() -> f32 {
    1.2
}

impl From<WafConfigJson> for WafConfig {
    fn from(json: WafConfigJson) -> Self {
        WafConfig {
            paranoia_level: json.paranoia_level,
            sqli_enabled: json.sqli,
            xss_enabled: json.xss,
            path_traversal_enabled: json.path_traversal,
            command_injection_enabled: json.command_injection,
            protocol_enabled: json.protocol,
            block_mode: json.block_mode,
            exclude_paths: json.exclude_paths,
            body_inspection_enabled: json.body_inspection,
            max_body_size: json.max_body_size,
            response_inspection_enabled: json.response_inspection,
            scoring: json.scoring.unwrap_or_default(),
            rules: json.rules.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_selector_id() {
        let selector = RuleSelector::Id(942100);
        assert!(selector.matches(942100, &[]));
        assert!(!selector.matches(942101, &[]));
    }

    #[test]
    fn test_rule_selector_wildcard() {
        let selector = RuleSelector::Pattern("942*".to_string());
        assert!(selector.matches(942100, &[]));
        assert!(selector.matches(942999, &[]));
        assert!(!selector.matches(941100, &[]));
    }

    #[test]
    fn test_rule_selector_range() {
        let selector = RuleSelector::Pattern("942100-942199".to_string());
        assert!(selector.matches(942100, &[]));
        assert!(selector.matches(942150, &[]));
        assert!(selector.matches(942199, &[]));
        assert!(!selector.matches(942200, &[]));
        assert!(!selector.matches(942099, &[]));
    }

    #[test]
    fn test_rule_selector_tag() {
        let selector = RuleSelector::Pattern("@sqli-union".to_string());
        assert!(selector.matches(942100, &["sqli-union".to_string()]));
        assert!(!selector.matches(942100, &["sqli-blind".to_string()]));
    }

    #[test]
    fn test_location_weights() {
        let weights = LocationWeights::default();
        assert_eq!(weights.get("query"), 1.5);
        assert_eq!(weights.get("path"), 1.2);
        assert_eq!(weights.get("header:User-Agent"), 1.0);
        assert_eq!(weights.get("body"), 1.2);
    }

    #[test]
    fn test_scoring_config_default() {
        let config = ScoringConfig::default();
        assert!(config.enabled);
        assert_eq!(config.block_threshold, 25);
        assert_eq!(config.log_threshold, 10);
    }
}
