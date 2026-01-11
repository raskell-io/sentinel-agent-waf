//! Insecure Deserialization Rules

use crate::rules::{AttackType, Confidence, Rule, RuleBuilder, Severity};
use anyhow::Result;

pub fn rules(paranoia_level: u8) -> Result<Vec<Rule>> {
    let all_rules = vec![
        // Java deserialization
        RuleBuilder::new(937100, "Deserialization: Java serialized object")
            .description("Detects Java serialized object magic bytes")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(rO0AB|aced0005)")
            .base_score(10)
            .cwe(502)
            .owasp("A08:2021-Software and Data Integrity Failures")
            .tags(&["deserialization", "java"])
            .build()?,

        RuleBuilder::new(937101, "Deserialization: Java Commons Collections")
            .description("Detects Java Commons Collections gadget chains")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(org\.apache\.commons\.collections\.(functors|map)|InvokerTransformer|ConstantTransformer)")
            .base_score(10)
            .cwe(502)
            .tags(&["deserialization", "java", "gadget"])
            .build()?,

        RuleBuilder::new(937102, "Deserialization: Java Spring gadgets")
            .description("Detects Spring framework gadget chains")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(org\.springframework\.(beans|aop)|MethodInvoker|PropertyPathFactoryBean)")
            .base_score(10)
            .cwe(502)
            .tags(&["deserialization", "java", "spring"])
            .build()?,

        RuleBuilder::new(937103, "Deserialization: Java JNDI injection")
            .description("Detects Java JNDI lookup injection (Log4Shell)")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\$\{(jndi|env|sys|java|lower|upper|date):.*\}")
            .base_score(10)
            .cwe(502)
            .cve("CVE-2021-44228")
            .tags(&["deserialization", "java", "log4shell", "jndi"])
            .build()?,

        RuleBuilder::new(937104, "Deserialization: Java OGNL")
            .description("Detects OGNL expression injection")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(\#|@)ognl|%\{.*\}|#context\[")
            .base_score(10)
            .cwe(917)
            .tags(&["deserialization", "java", "ognl"])
            .build()?,

        // PHP deserialization
        RuleBuilder::new(937110, "Deserialization: PHP object serialization")
            .description("Detects PHP serialized object patterns")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(O:\d+:|a:\d+:\{|s:\d+:)")
            .base_score(9)
            .cwe(502)
            .tags(&["deserialization", "php"])
            .build()?,

        RuleBuilder::new(937111, "Deserialization: PHP __wakeup/__destruct")
            .description("Detects PHP magic method references")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(__wakeup|__destruct|__toString|__call)")
            .base_score(9)
            .cwe(502)
            .tags(&["deserialization", "php", "magic-method"])
            .build()?,

        RuleBuilder::new(937112, "Deserialization: PHP POP chain")
            .description("Detects common PHP POP gadget chains")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(Monolog\\Handler|Guzzle\\Psr7|Symfony\\Component)")
            .base_score(9)
            .cwe(502)
            .tags(&["deserialization", "php", "gadget"])
            .build()?,

        // Python deserialization
        RuleBuilder::new(937120, "Deserialization: Python pickle")
            .description("Detects Python pickle protocol markers")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(c__builtin__|cposix|cos\nsystem|creduce)")
            .base_score(10)
            .cwe(502)
            .tags(&["deserialization", "python", "pickle"])
            .build()?,

        RuleBuilder::new(937121, "Deserialization: Python PyYAML")
            .description("Detects PyYAML unsafe load patterns")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(!!python/object|!!python/module|yaml\.unsafe_load)")
            .base_score(10)
            .cwe(502)
            .tags(&["deserialization", "python", "yaml"])
            .build()?,

        // .NET deserialization
        RuleBuilder::new(937130, "Deserialization: .NET BinaryFormatter")
            .description("Detects .NET BinaryFormatter serialization")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(BinaryFormatter|SoapFormatter|LosFormatter|ObjectStateFormatter)")
            .base_score(10)
            .cwe(502)
            .tags(&["deserialization", "dotnet"])
            .build()?,

        RuleBuilder::new(937131, "Deserialization: .NET TypeNameHandling")
            .description("Detects .NET JSON TypeNameHandling exploitation")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r#"(?i)"\$type"\s*:\s*"(System\.Web|System\.Windows|Microsoft\.)"#)
            .base_score(10)
            .cwe(502)
            .tags(&["deserialization", "dotnet", "json"])
            .build()?,

        RuleBuilder::new(937132, "Deserialization: .NET ViewState")
            .description("Detects suspicious .NET ViewState patterns")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::High)
            .confidence(Confidence::Medium)
            .paranoia(2)
            .pattern(r"(?i)(__VIEWSTATE|__EVENTVALIDATION|__VIEWSTATEGENERATOR)")
            .base_score(6)
            .cwe(502)
            .tags(&["deserialization", "dotnet", "viewstate"])
            .build()?,

        // Ruby deserialization
        RuleBuilder::new(937140, "Deserialization: Ruby Marshal")
            .description("Detects Ruby Marshal.load patterns")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(\x04\x08o:|Marshal\.load|YAML\.load)")
            .base_score(10)
            .cwe(502)
            .tags(&["deserialization", "ruby"])
            .build()?,

        RuleBuilder::new(937141, "Deserialization: Ruby ERB injection")
            .description("Detects Ruby ERB template injection")
            .attack_type(AttackType::Deserialization)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"<%=?\s*(system|exec|`|IO\.)")
            .base_score(10)
            .cwe(502)
            .tags(&["deserialization", "ruby", "erb"])
            .build()?,
    ];

    Ok(all_rules
        .into_iter()
        .filter(|r| r.paranoia_level <= paranoia_level)
        .collect())
}
