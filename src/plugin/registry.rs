//! Plugin Registry
//!
//! Manages plugin registration, lifecycle, and execution.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use indexmap::IndexMap;
use tracing::{debug, info};

use super::{
    DetectionPlugin, PluginInfo, PluginOutput, PluginPhase, RequestContext, RulePlugin,
    ScoringPlugin,
};
use crate::detection::{AnomalyScore, Detection};
use crate::rules::Rule;

/// Plugin registry for managing all registered plugins
pub struct PluginRegistry {
    /// Rule plugins (insertion-ordered)
    rule_plugins: IndexMap<String, Arc<dyn RulePlugin>>,
    /// Detection plugins (insertion-ordered)
    detection_plugins: IndexMap<String, Arc<dyn DetectionPlugin>>,
    /// Scoring plugins (insertion-ordered)
    scoring_plugins: IndexMap<String, Arc<dyn ScoringPlugin>>,
    /// Cached rules from rule plugins
    cached_rules: Vec<Rule>,
    /// Whether the registry has been initialized
    initialized: bool,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    /// Create a new empty plugin registry
    pub fn new() -> Self {
        Self {
            rule_plugins: IndexMap::new(),
            detection_plugins: IndexMap::new(),
            scoring_plugins: IndexMap::new(),
            cached_rules: Vec::new(),
            initialized: false,
        }
    }

    /// Register a rule plugin
    pub fn register_rule_plugin(&mut self, plugin: Arc<dyn RulePlugin>) {
        let info = plugin.info();
        info!(
            plugin_id = %info.id,
            plugin_name = %info.name,
            "Registering rule plugin"
        );
        self.rule_plugins.insert(info.id.clone(), plugin);
        self.initialized = false; // Mark for re-initialization
    }

    /// Register a detection plugin
    pub fn register_detection_plugin(&mut self, plugin: Arc<dyn DetectionPlugin>) {
        let info = plugin.info();
        info!(
            plugin_id = %info.id,
            plugin_name = %info.name,
            "Registering detection plugin"
        );
        self.detection_plugins.insert(info.id.clone(), plugin);
    }

    /// Register a scoring plugin
    pub fn register_scoring_plugin(&mut self, plugin: Arc<dyn ScoringPlugin>) {
        let info = plugin.info();
        info!(
            plugin_id = %info.id,
            plugin_name = %info.name,
            "Registering scoring plugin"
        );
        self.scoring_plugins.insert(info.id.clone(), plugin);
    }

    /// Initialize all plugins with their configurations
    pub fn initialize(&mut self, configs: &HashMap<String, serde_json::Value>) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        // Initialize rule plugins and collect rules
        self.cached_rules.clear();
        for (id, plugin) in &self.rule_plugins {
            let _config = configs.get(id).cloned().unwrap_or(serde_json::Value::Null);

            // Note: We can't call initialize on Arc<dyn RulePlugin> without inner mutability
            // This would require RefCell or similar. For now, we just collect rules.
            let rules = plugin.rules();
            info!(
                plugin_id = %id,
                rules_count = rules.len(),
                "Loaded rules from plugin"
            );
            self.cached_rules.extend(rules);
        }

        self.initialized = true;
        info!(
            rule_plugins = self.rule_plugins.len(),
            detection_plugins = self.detection_plugins.len(),
            scoring_plugins = self.scoring_plugins.len(),
            total_plugin_rules = self.cached_rules.len(),
            "Plugin registry initialized"
        );

        Ok(())
    }

    /// Get all rules from rule plugins
    pub fn plugin_rules(&self) -> &[Rule] {
        &self.cached_rules
    }

    /// Execute detection plugins
    pub fn run_detection_plugins(
        &self,
        value: &str,
        location: &str,
        context: &RequestContext,
    ) -> Vec<PluginOutput> {
        let mut outputs = Vec::new();

        for (id, plugin) in &self.detection_plugins {
            let info = plugin.info();
            if !info.enabled {
                continue;
            }

            if !info.phases.contains(&PluginPhase::Detection) {
                continue;
            }

            debug!(plugin_id = %id, location = location, "Running detection plugin");
            let output = plugin.detect(value, location, context);

            if !output.detections.is_empty() || output.score_adjustment != 0 {
                debug!(
                    plugin_id = %id,
                    detections = output.detections.len(),
                    score_adjustment = output.score_adjustment,
                    "Detection plugin produced output"
                );
            }

            if output.skip_remaining {
                outputs.push(output);
                break;
            }

            outputs.push(output);
        }

        outputs
    }

    /// Execute scoring plugins
    pub fn run_scoring_plugins(
        &self,
        context: &RequestContext,
        detections: &[Detection],
        score: &AnomalyScore,
    ) -> Vec<PluginOutput> {
        let mut outputs = Vec::new();

        for (id, plugin) in &self.scoring_plugins {
            let info = plugin.info();
            if !info.enabled {
                continue;
            }

            if !info.phases.contains(&PluginPhase::Scoring) {
                continue;
            }

            debug!(plugin_id = %id, "Running scoring plugin");
            let output = plugin.adjust_score(context, detections, score);

            if output.score_adjustment != 0 {
                debug!(
                    plugin_id = %id,
                    score_adjustment = output.score_adjustment,
                    "Scoring plugin adjusted score"
                );
            }

            if output.skip_remaining {
                outputs.push(output);
                break;
            }

            outputs.push(output);
        }

        outputs
    }

    /// Get all plugin info
    pub fn list_plugins(&self) -> Vec<PluginInfo> {
        let mut infos = Vec::new();

        for plugin in self.rule_plugins.values() {
            infos.push(plugin.info());
        }
        for plugin in self.detection_plugins.values() {
            infos.push(plugin.info());
        }
        for plugin in self.scoring_plugins.values() {
            infos.push(plugin.info());
        }

        infos
    }

    /// Check if any plugins are registered
    pub fn has_plugins(&self) -> bool {
        !self.rule_plugins.is_empty()
            || !self.detection_plugins.is_empty()
            || !self.scoring_plugins.is_empty()
    }

    /// Get count of registered plugins
    pub fn plugin_count(&self) -> usize {
        self.rule_plugins.len() + self.detection_plugins.len() + self.scoring_plugins.len()
    }

    /// Unregister a plugin by ID
    pub fn unregister(&mut self, plugin_id: &str) -> bool {
        let removed = self.rule_plugins.shift_remove(plugin_id).is_some()
            || self.detection_plugins.shift_remove(plugin_id).is_some()
            || self.scoring_plugins.shift_remove(plugin_id).is_some();

        if removed {
            info!(plugin_id = plugin_id, "Unregistered plugin");
            self.initialized = false;
        }

        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock rule plugin for testing
    #[allow(dead_code)]
    struct MockRulePlugin {
        info: PluginInfo,
        rules: Vec<Rule>,
    }

    impl RulePlugin for MockRulePlugin {
        fn info(&self) -> PluginInfo {
            self.info.clone()
        }

        fn initialize(&mut self, _config: serde_json::Value) -> Result<()> {
            Ok(())
        }

        fn rules(&self) -> Vec<Rule> {
            self.rules.clone()
        }
    }

    // Mock detection plugin for testing
    struct MockDetectionPlugin {
        info: PluginInfo,
        output: PluginOutput,
    }

    impl DetectionPlugin for MockDetectionPlugin {
        fn info(&self) -> PluginInfo {
            self.info.clone()
        }

        fn initialize(&mut self, _config: serde_json::Value) -> Result<()> {
            Ok(())
        }

        fn detect(&self, _value: &str, _location: &str, _context: &RequestContext) -> PluginOutput {
            self.output.clone()
        }
    }

    // Mock scoring plugin for testing
    struct MockScoringPlugin {
        info: PluginInfo,
        adjustment: i32,
    }

    impl ScoringPlugin for MockScoringPlugin {
        fn info(&self) -> PluginInfo {
            self.info.clone()
        }

        fn initialize(&mut self, _config: serde_json::Value) -> Result<()> {
            Ok(())
        }

        fn adjust_score(
            &self,
            _context: &RequestContext,
            _detections: &[Detection],
            _score: &AnomalyScore,
        ) -> PluginOutput {
            PluginOutput::with_score_adjustment(self.adjustment)
        }
    }

    #[test]
    fn test_registry_empty() {
        let registry = PluginRegistry::new();
        assert!(!registry.has_plugins());
        assert_eq!(registry.plugin_count(), 0);
    }

    #[test]
    fn test_register_detection_plugin() {
        let mut registry = PluginRegistry::new();

        let plugin = MockDetectionPlugin {
            info: PluginInfo::new("mock-detection", "Mock Detection", "1.0.0")
                .with_phases(vec![PluginPhase::Detection]),
            output: PluginOutput::empty(),
        };

        registry.register_detection_plugin(Arc::new(plugin));

        assert!(registry.has_plugins());
        assert_eq!(registry.plugin_count(), 1);

        let plugins = registry.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].id, "mock-detection");
    }

    #[test]
    fn test_run_detection_plugins() {
        let mut registry = PluginRegistry::new();

        let plugin = MockDetectionPlugin {
            info: PluginInfo::new("mock-detection", "Mock Detection", "1.0.0")
                .with_phases(vec![PluginPhase::Detection]),
            output: PluginOutput::empty().add_tag("from-plugin"),
        };

        registry.register_detection_plugin(Arc::new(plugin));

        let context = RequestContext::default();
        let outputs = registry.run_detection_plugins("test input", "body", &context);

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].tags, vec!["from-plugin"]);
    }

    #[test]
    fn test_run_scoring_plugins() {
        let mut registry = PluginRegistry::new();

        let plugin = MockScoringPlugin {
            info: PluginInfo::new("mock-scoring", "Mock Scoring", "1.0.0")
                .with_phases(vec![PluginPhase::Scoring]),
            adjustment: -5,
        };

        registry.register_scoring_plugin(Arc::new(plugin));

        let context = RequestContext::default();
        let outputs = registry.run_scoring_plugins(&context, &[], &AnomalyScore::default());

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].score_adjustment, -5);
    }

    #[test]
    fn test_unregister_plugin() {
        let mut registry = PluginRegistry::new();

        let plugin = MockDetectionPlugin {
            info: PluginInfo::new("mock-detection", "Mock Detection", "1.0.0")
                .with_phases(vec![PluginPhase::Detection]),
            output: PluginOutput::empty(),
        };

        registry.register_detection_plugin(Arc::new(plugin));
        assert!(registry.has_plugins());

        let removed = registry.unregister("mock-detection");
        assert!(removed);
        assert!(!registry.has_plugins());

        // Should return false for non-existent plugin
        let removed = registry.unregister("non-existent");
        assert!(!removed);
    }

    #[test]
    fn test_skip_remaining() {
        let mut registry = PluginRegistry::new();

        // First plugin that signals skip_remaining
        let plugin1 = MockDetectionPlugin {
            info: PluginInfo::new("plugin-1", "Plugin 1", "1.0.0")
                .with_phases(vec![PluginPhase::Detection]),
            output: PluginOutput::empty().skip_remaining(),
        };

        // Second plugin that should be skipped
        let plugin2 = MockDetectionPlugin {
            info: PluginInfo::new("plugin-2", "Plugin 2", "1.0.0")
                .with_phases(vec![PluginPhase::Detection]),
            output: PluginOutput::empty().add_tag("should-not-run"),
        };

        registry.register_detection_plugin(Arc::new(plugin1));
        registry.register_detection_plugin(Arc::new(plugin2));

        let context = RequestContext::default();
        let outputs = registry.run_detection_plugins("test", "body", &context);

        // Only first plugin should have run
        assert_eq!(outputs.len(), 1);
        assert!(outputs[0].skip_remaining);
    }
}
