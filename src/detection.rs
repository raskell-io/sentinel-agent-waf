//! Detection types and results
//!
//! Types for representing WAF detections and scoring results.

use serde::Serialize;
use std::collections::HashMap;

use crate::rules::AttackType;

/// Detection result from a single rule match
#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    /// Rule ID that triggered
    pub rule_id: u32,
    /// Rule name
    pub rule_name: String,
    /// Attack type
    pub attack_type: AttackType,
    /// Matched content
    pub matched_value: String,
    /// Location where match occurred
    pub location: String,
    /// Base score from rule
    pub base_score: u32,
    /// Tags from rule
    pub tags: Vec<String>,
}

/// Score contribution from a single rule match
#[derive(Debug, Clone, Serialize)]
pub struct RuleScore {
    /// Rule ID
    pub rule_id: u32,
    /// Base score from rule definition
    pub base_score: u32,
    /// Location weight multiplier
    pub location_weight: f32,
    /// Severity weight multiplier
    pub severity_weight: f32,
    /// Final calculated score
    pub final_score: u32,
}

/// Accumulated anomaly score for a request
#[derive(Debug, Clone, Default, Serialize)]
pub struct AnomalyScore {
    /// Total anomaly score
    pub total: u32,
    /// Score by attack category
    pub by_category: HashMap<AttackType, u32>,
    /// Contributing rule scores
    pub contributing_rules: Vec<RuleScore>,
}

impl AnomalyScore {
    /// Create a new empty score
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a detection to the score
    pub fn add(&mut self, detection: &Detection, location_weight: f32, severity_weight: f32) {
        let final_score =
            (detection.base_score as f32 * location_weight * severity_weight).round() as u32;

        self.total += final_score;
        *self.by_category.entry(detection.attack_type).or_insert(0) += final_score;

        self.contributing_rules.push(RuleScore {
            rule_id: detection.rule_id,
            base_score: detection.base_score,
            location_weight,
            severity_weight,
            final_score,
        });
    }

    /// Check if score exceeds block threshold
    pub fn should_block(&self, threshold: u32) -> bool {
        self.total >= threshold
    }

    /// Check if score exceeds log threshold
    pub fn should_log(&self, threshold: u32) -> bool {
        self.total >= threshold
    }

    /// Get the highest scoring attack category
    pub fn top_category(&self) -> Option<AttackType> {
        self.by_category
            .iter()
            .max_by_key(|(_, score)| *score)
            .map(|(cat, _)| *cat)
    }
}

/// Decision result from WAF evaluation
#[derive(Debug, Clone)]
pub enum WafDecision {
    /// Allow the request
    Allow,
    /// Allow but log (score above log threshold)
    AllowWithWarning { score: AnomalyScore },
    /// Block the request
    Block { score: AnomalyScore },
}

impl WafDecision {
    /// Check if this is a blocking decision
    pub fn is_block(&self) -> bool {
        matches!(self, WafDecision::Block { .. })
    }

    /// Get the score if available
    pub fn score(&self) -> Option<&AnomalyScore> {
        match self {
            WafDecision::Allow => None,
            WafDecision::AllowWithWarning { score } | WafDecision::Block { score } => Some(score),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_detection(rule_id: u32, attack_type: AttackType, base_score: u32) -> Detection {
        Detection {
            rule_id,
            rule_name: format!("Rule {}", rule_id),
            attack_type,
            matched_value: "test".to_string(),
            location: "query".to_string(),
            base_score,
            tags: vec![],
        }
    }

    #[test]
    fn test_anomaly_score_accumulation() {
        let mut score = AnomalyScore::new();

        let det1 = make_detection(942100, AttackType::SqlInjection, 9);
        let det2 = make_detection(942110, AttackType::SqlInjection, 7);

        score.add(&det1, 1.5, 2.0); // 9 * 1.5 * 2.0 = 27
        score.add(&det2, 1.5, 1.5); // 7 * 1.5 * 1.5 = 15.75 -> 16

        assert_eq!(score.total, 43);
        assert_eq!(score.by_category.get(&AttackType::SqlInjection), Some(&43));
        assert_eq!(score.contributing_rules.len(), 2);
    }

    #[test]
    fn test_score_thresholds() {
        let mut score = AnomalyScore::new();
        let det = make_detection(942100, AttackType::SqlInjection, 10);
        score.add(&det, 1.0, 1.0);

        assert!(!score.should_block(25));
        assert!(score.should_log(10));
        assert!(!score.should_log(15));
    }

    #[test]
    fn test_top_category() {
        let mut score = AnomalyScore::new();

        let det1 = make_detection(942100, AttackType::SqlInjection, 5);
        let det2 = make_detection(941100, AttackType::Xss, 10);

        score.add(&det1, 1.0, 1.0);
        score.add(&det2, 1.0, 1.0);

        assert_eq!(score.top_category(), Some(AttackType::Xss));
    }
}
