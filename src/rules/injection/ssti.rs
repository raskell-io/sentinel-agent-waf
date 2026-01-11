//! Server-Side Template Injection (SSTI) Rules

use crate::rules::{AttackType, Confidence, Rule, RuleBuilder, Severity};
use anyhow::Result;

pub fn rules(paranoia_level: u8) -> Result<Vec<Rule>> {
    let all_rules = vec![
        // Generic SSTI
        RuleBuilder::new(935100, "SSTI: Template expression {{")
            .description("Detects generic template expression syntax")
            .attack_type(AttackType::Ssti)
            .severity(Severity::High)
            .confidence(Confidence::Medium)
            .paranoia(1)
            .pattern(r"\{\{.*\}\}")
            .base_score(7)
            .cwe(1336)
            .tags(&["ssti", "template"])
            .build()?,

        RuleBuilder::new(935101, "SSTI: Template expression ${")
            .description("Detects ${} template expression syntax")
            .attack_type(AttackType::Ssti)
            .severity(Severity::High)
            .confidence(Confidence::Medium)
            .paranoia(1)
            .pattern(r"\$\{.*\}")
            .base_score(7)
            .cwe(1336)
            .tags(&["ssti", "template"])
            .build()?,

        RuleBuilder::new(935102, "SSTI: Template expression <%")
            .description("Detects <% %> template expression syntax")
            .attack_type(AttackType::Ssti)
            .severity(Severity::High)
            .confidence(Confidence::Medium)
            .paranoia(1)
            .pattern(r"<%.*%>")
            .base_score(7)
            .cwe(1336)
            .tags(&["ssti", "template"])
            .build()?,

        // Jinja2 / Python
        RuleBuilder::new(935110, "SSTI: Jinja2 config access")
            .description("Detects Jinja2 config attribute access")
            .attack_type(AttackType::Ssti)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\{\{\s*config\s*\}\}|\{\{\s*request\.")
            .base_score(9)
            .cwe(1336)
            .tags(&["ssti", "jinja2", "python"])
            .build()?,

        RuleBuilder::new(935111, "SSTI: Jinja2 class access")
            .description("Detects Jinja2 __class__ attribute access")
            .attack_type(AttackType::Ssti)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)__class__|__mro__|__subclasses__|__globals__|__builtins__")
            .base_score(10)
            .cwe(1336)
            .tags(&["ssti", "jinja2", "python", "rce"])
            .build()?,

        RuleBuilder::new(935112, "SSTI: Jinja2 popen/system")
            .description("Detects Jinja2 command execution")
            .attack_type(AttackType::Ssti)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(popen|system|subprocess|os\.)")
            .base_score(10)
            .cwe(1336)
            .tags(&["ssti", "jinja2", "python", "rce"])
            .build()?,

        // Twig (PHP)
        RuleBuilder::new(935120, "SSTI: Twig filter")
            .description("Detects Twig filter syntax")
            .attack_type(AttackType::Ssti)
            .severity(Severity::High)
            .confidence(Confidence::Medium)
            .paranoia(2)
            .pattern(r"\{\{\s*[^}]+\|")
            .base_score(6)
            .cwe(1336)
            .tags(&["ssti", "twig", "php"])
            .build()?,

        RuleBuilder::new(935121, "SSTI: Twig _self access")
            .description("Detects Twig _self attribute access")
            .attack_type(AttackType::Ssti)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)_self\.env\.registerUndefinedFilterCallback")
            .base_score(10)
            .cwe(1336)
            .tags(&["ssti", "twig", "php", "rce"])
            .build()?,

        // Freemarker (Java)
        RuleBuilder::new(935130, "SSTI: Freemarker built-ins")
            .description("Detects Freemarker built-in functions")
            .attack_type(AttackType::Ssti)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\?\s*(new|api|exec|eval)")
            .base_score(9)
            .cwe(1336)
            .tags(&["ssti", "freemarker", "java"])
            .build()?,

        RuleBuilder::new(935131, "SSTI: Freemarker Execute")
            .description("Detects Freemarker Execute class")
            .attack_type(AttackType::Ssti)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)freemarker\.template\.utility\.Execute")
            .base_score(10)
            .cwe(1336)
            .tags(&["ssti", "freemarker", "java", "rce"])
            .build()?,

        // Velocity (Java)
        RuleBuilder::new(935140, "SSTI: Velocity class loading")
            .description("Detects Velocity class loading")
            .attack_type(AttackType::Ssti)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\$class\.inspect|\.getClass\(\)")
            .base_score(9)
            .cwe(1336)
            .tags(&["ssti", "velocity", "java"])
            .build()?,

        RuleBuilder::new(935141, "SSTI: Velocity Runtime")
            .description("Detects Velocity Runtime access")
            .attack_type(AttackType::Ssti)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\$\w+\.class\.forName|java\.lang\.Runtime")
            .base_score(10)
            .cwe(1336)
            .tags(&["ssti", "velocity", "java", "rce"])
            .build()?,

        // Smarty (PHP)
        RuleBuilder::new(935150, "SSTI: Smarty php tag")
            .description("Detects Smarty php tag injection")
            .attack_type(AttackType::Ssti)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\{php\}|\{/php\}")
            .base_score(10)
            .cwe(1336)
            .tags(&["ssti", "smarty", "php", "rce"])
            .build()?,

        // Handlebars/Mustache
        RuleBuilder::new(935160, "SSTI: Handlebars helper injection")
            .description("Detects Handlebars helper injection")
            .attack_type(AttackType::Ssti)
            .severity(Severity::High)
            .confidence(Confidence::Medium)
            .paranoia(2)
            .pattern(r"\{\{#with\s+|\{\{#each\s+")
            .base_score(6)
            .cwe(1336)
            .tags(&["ssti", "handlebars", "javascript"])
            .build()?,

        // ERB (Ruby)
        RuleBuilder::new(935170, "SSTI: ERB code execution")
            .description("Detects ERB code execution")
            .attack_type(AttackType::Ssti)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"<%=?\s*(system|exec|`|eval|IO\.)")
            .base_score(10)
            .cwe(1336)
            .tags(&["ssti", "erb", "ruby", "rce"])
            .build()?,
    ];

    Ok(all_rules
        .into_iter()
        .filter(|r| r.paranoia_level <= paranoia_level)
        .collect())
}
