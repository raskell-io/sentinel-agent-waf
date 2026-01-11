//! Path Traversal and File Inclusion Rules

use crate::rules::{AttackType, Confidence, Rule, RuleBuilder, Severity};
use anyhow::Result;

pub fn rules(paranoia_level: u8) -> Result<Vec<Rule>> {
    let all_rules = vec![
        // Basic path traversal
        RuleBuilder::new(930100, "Path Traversal: Basic ../ sequence")
            .description("Detects basic directory traversal")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"\.\.(/|\\)")
            .base_score(8)
            .cwe(22)
            .owasp("A01:2021-Broken Access Control")
            .tags(&["traversal", "lfi"])
            .build()?,

        RuleBuilder::new(930101, "Path Traversal: URL encoded ..%2f")
            .description("Detects URL-encoded path traversal")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(\.\.%2f|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./)")
            .base_score(9)
            .cwe(22)
            .tags(&["traversal", "lfi", "encoded"])
            .build()?,

        RuleBuilder::new(930102, "Path Traversal: Double URL encoded")
            .description("Detects double URL-encoded path traversal")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(%252e%252e|%252f|%255c)")
            .base_score(9)
            .cwe(22)
            .tags(&["traversal", "lfi", "encoded"])
            .build()?,

        RuleBuilder::new(930103, "Path Traversal: UTF-8 encoded")
            .description("Detects UTF-8 encoded path traversal")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(%c0%ae|%c1%9c|%c0%af)")
            .base_score(9)
            .cwe(22)
            .tags(&["traversal", "lfi", "encoded"])
            .build()?,

        RuleBuilder::new(930104, "Path Traversal: Backslash variant")
            .description("Detects backslash path traversal (Windows)")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"\.\.\\")
            .base_score(8)
            .cwe(22)
            .tags(&["traversal", "lfi", "windows"])
            .build()?,

        // OS file access
        RuleBuilder::new(930110, "Path Traversal: /etc/passwd access")
            .description("Detects Linux password file access")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)/etc/(passwd|shadow|group|hosts)")
            .base_score(10)
            .cwe(22)
            .tags(&["traversal", "lfi", "unix"])
            .build()?,

        RuleBuilder::new(930111, "Path Traversal: /proc access")
            .description("Detects Linux proc filesystem access")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)/proc/(self|[0-9]+)/(environ|cmdline|fd|maps)")
            .base_score(9)
            .cwe(22)
            .tags(&["traversal", "lfi", "unix"])
            .build()?,

        RuleBuilder::new(930112, "Path Traversal: Windows system files")
            .description("Detects Windows system file access")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(c:\\windows|c:\\winnt|c:\\boot\.ini|c:\\system32)")
            .base_score(10)
            .cwe(22)
            .tags(&["traversal", "lfi", "windows"])
            .build()?,

        RuleBuilder::new(930113, "Path Traversal: Config file access")
            .description("Detects common config file access")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(\.htaccess|\.htpasswd|\.env|wp-config\.php|config\.php)")
            .base_score(9)
            .cwe(22)
            .tags(&["traversal", "lfi", "config"])
            .build()?,

        // Local File Inclusion
        RuleBuilder::new(930120, "LFI: PHP wrapper php://")
            .description("Detects PHP stream wrapper")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)php://(input|filter|data)")
            .base_score(10)
            .cwe(98)
            .tags(&["lfi", "rfi", "php"])
            .build()?,

        RuleBuilder::new(930121, "LFI: PHP expect wrapper")
            .description("Detects PHP expect:// for command execution")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)expect://")
            .base_score(10)
            .cwe(98)
            .tags(&["lfi", "rfi", "php", "rce"])
            .build()?,

        RuleBuilder::new(930122, "LFI: file:// protocol")
            .description("Detects file:// protocol usage")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)file://")
            .base_score(8)
            .cwe(22)
            .tags(&["lfi", "file-protocol"])
            .build()?,

        RuleBuilder::new(930123, "LFI: Null byte injection")
            .description("Detects null byte for extension bypass")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(%00|\\x00|\x00)")
            .base_score(9)
            .cwe(626)
            .tags(&["lfi", "null-byte"])
            .build()?,

        // Remote File Inclusion
        RuleBuilder::new(930130, "RFI: HTTP include")
            .description("Detects HTTP URL in include parameter")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(file|include|require|page|path|doc|template|folder)=https?://")
            .base_score(10)
            .cwe(98)
            .tags(&["rfi", "remote"])
            .build()?,

        RuleBuilder::new(930131, "RFI: FTP include")
            .description("Detects FTP URL in include parameter")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(file|include|require|page)=ftp://")
            .base_score(10)
            .cwe(98)
            .tags(&["rfi", "remote"])
            .build()?,

        // Log poisoning
        RuleBuilder::new(930140, "LFI: Log file access")
            .description("Detects log file access for poisoning")
            .attack_type(AttackType::PathTraversal)
            .severity(Severity::High)
            .confidence(Confidence::Medium)
            .paranoia(2)
            .pattern(r"(?i)/(var/log|apache|nginx|httpd)/.+\.log")
            .base_score(7)
            .cwe(22)
            .tags(&["lfi", "log-poisoning"])
            .build()?,
    ];

    Ok(all_rules
        .into_iter()
        .filter(|r| r.paranoia_level <= paranoia_level)
        .collect())
}
