//! WAF Engine
//!
//! The core detection engine that evaluates rules against incoming requests.

use anyhow::Result;
use std::collections::HashMap;
use tracing::{debug, info};

use crate::config::WafConfig;
use crate::detection::Detection;
use crate::rules::{self, Rule};

/// WAF engine - the core detection component
pub struct WafEngine {
    /// Active rules (filtered by config)
    rules: Vec<Rule>,
    /// Current configuration
    pub config: WafConfig,
}

impl WafEngine {
    /// Create a new WAF engine with the given configuration
    pub fn new(config: WafConfig) -> Result<Self> {
        // Load all rules based on category settings and paranoia level
        let all_rules = rules::load_rules(&config)?;

        // Apply rule management filters
        let rules = rules::filter_rules(
            &all_rules,
            config.rules.enabled.as_deref(),
            &config.rules.disabled,
        );

        info!(
            rules_count = rules.len(),
            paranoia_level = config.paranoia_level,
            "WAF engine initialized"
        );

        Ok(Self { rules, config })
    }

    /// Get all active rules
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Check a value against all applicable rules for a location
    pub fn check(&self, value: &str, location: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for rule in &self.rules {
            // Check if rule applies to this location
            if !rule.applies_to(location) {
                continue;
            }

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
                    base_score: rule.base_score,
                    tags: rule.tags.clone(),
                });
            }
        }

        detections
    }

    /// Check entire request (path, query, headers)
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

    /// Check if path should be excluded from inspection
    pub fn is_excluded(&self, path: &str) -> bool {
        self.config
            .exclude_paths
            .iter()
            .any(|p| path.starts_with(p))
    }

    /// Get rule by ID
    pub fn get_rule(&self, id: u32) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// Check if an exclusion applies to the current request context
    pub fn check_exclusion(
        &self,
        rule_id: u32,
        path: &str,
        _source_ip: Option<&str>,
        _method: Option<&str>,
        _headers: Option<&HashMap<String, Vec<String>>>,
    ) -> bool {
        let rule = match self.get_rule(rule_id) {
            Some(r) => r,
            None => return false,
        };

        for exclusion in &self.config.rules.exclusions {
            // Check if exclusion applies to this rule
            let rule_matches = exclusion
                .rules
                .iter()
                .any(|s| s.matches(rule_id, &rule.tags));

            if !rule_matches {
                continue;
            }

            // Check path condition
            if let Some(paths) = &exclusion.conditions.paths {
                if paths.iter().any(|p| path.starts_with(p)) {
                    debug!(rule_id = rule_id, path = path, "Rule excluded by path");
                    return true;
                }
            }

            // Additional conditions (IP, method, headers) can be added here
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> WafEngine {
        let config = WafConfig {
            paranoia_level: 2,
            ..Default::default()
        };
        WafEngine::new(config).unwrap()
    }

    #[test]
    fn test_engine_creation() {
        let engine = test_engine();
        assert!(!engine.rules().is_empty());
    }

    #[test]
    fn test_sqli_detection() {
        let engine = test_engine();
        let detections = engine.check("' OR '1'='1", "query");
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_xss_detection() {
        let engine = test_engine();
        let detections = engine.check("<script>alert('xss')</script>", "body");
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_path_exclusion() {
        let config = WafConfig {
            exclude_paths: vec!["/health".to_string(), "/metrics".to_string()],
            ..Default::default()
        };
        let engine = WafEngine::new(config).unwrap();

        assert!(engine.is_excluded("/health"));
        assert!(engine.is_excluded("/health/ready"));
        assert!(!engine.is_excluded("/api/users"));
    }

    #[test]
    fn test_check_request() {
        let engine = test_engine();
        let mut headers = HashMap::new();
        headers.insert(
            "User-Agent".to_string(),
            vec!["Mozilla/5.0".to_string()],
        );

        let detections = engine.check_request("/api/search", Some("q=UNION SELECT"), &headers);
        assert!(!detections.is_empty());
    }
}
