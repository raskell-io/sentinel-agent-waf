//! Command Injection Rules

use crate::rules::{AttackType, Confidence, Rule, RuleBuilder, Severity};
use anyhow::Result;

pub fn rules(paranoia_level: u8) -> Result<Vec<Rule>> {
    let all_rules = vec![
        // Unix command injection
        RuleBuilder::new(932100, "Command Injection: Pipe operator")
            .description("Detects pipe-based command injection")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\|\s*(cat|ls|id|whoami|pwd|uname|curl|wget|nc|bash|sh|python|perl|ruby|php)\b")
            .base_score(10)
            .cwe(78)
            .owasp("A03:2021-Injection")
            .tags(&["cmdi", "unix"])
            .build()?,

        RuleBuilder::new(932101, "Command Injection: Semicolon chaining")
            .description("Detects semicolon-based command chaining")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i);\s*(cat|ls|id|whoami|pwd|uname|curl|wget|nc|bash|sh)\b")
            .base_score(10)
            .cwe(78)
            .tags(&["cmdi", "unix"])
            .build()?,

        RuleBuilder::new(932102, "Command Injection: Backtick execution")
            .description("Detects backtick command substitution")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"`[^`]+`")
            .base_score(9)
            .cwe(78)
            .tags(&["cmdi", "unix"])
            .build()?,

        RuleBuilder::new(932103, "Command Injection: $() substitution")
            .description("Detects $() command substitution")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"\$\([^)]+\)")
            .base_score(9)
            .cwe(78)
            .tags(&["cmdi", "unix"])
            .build()?,

        RuleBuilder::new(932104, "Command Injection: && chaining")
            .description("Detects && command chaining")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)&&\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh|rm|chmod|chown)\b")
            .base_score(10)
            .cwe(78)
            .tags(&["cmdi", "unix"])
            .build()?,

        RuleBuilder::new(932105, "Command Injection: || chaining")
            .description("Detects || command chaining")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\|\|\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh)\b")
            .base_score(9)
            .cwe(78)
            .tags(&["cmdi", "unix"])
            .build()?,

        RuleBuilder::new(932106, "Command Injection: /bin path")
            .description("Detects direct /bin or /usr/bin execution")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)/(bin|usr/bin|sbin)/(sh|bash|dash|zsh|csh|ksh|python|perl|ruby|php)")
            .base_score(10)
            .cwe(78)
            .tags(&["cmdi", "unix"])
            .build()?,

        RuleBuilder::new(932107, "Command Injection: Reverse shell")
            .description("Detects common reverse shell patterns")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)(nc|ncat|netcat)\s+(-e|--exec|-c)\s+")
            .base_score(10)
            .cwe(78)
            .tags(&["cmdi", "reverse-shell"])
            .build()?,

        RuleBuilder::new(932108, "Command Injection: Bash reverse shell")
            .description("Detects bash reverse shell patterns")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)bash\s+-i\s+>&\s*/dev/tcp/")
            .base_score(10)
            .cwe(78)
            .tags(&["cmdi", "reverse-shell"])
            .build()?,

        // Windows command injection
        RuleBuilder::new(932120, "Command Injection: cmd.exe")
            .description("Detects Windows cmd.exe execution")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)cmd(\.exe)?\s*/c\s+")
            .base_score(10)
            .cwe(78)
            .tags(&["cmdi", "windows"])
            .build()?,

        RuleBuilder::new(932121, "Command Injection: PowerShell")
            .description("Detects PowerShell execution")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)powershell(\.exe)?\s+(-e\s+|-enc\s+|-command\s+|-nop\s+)")
            .base_score(10)
            .cwe(78)
            .tags(&["cmdi", "windows", "powershell"])
            .build()?,

        RuleBuilder::new(932122, "Command Injection: PowerShell encoded")
            .description("Detects base64-encoded PowerShell")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)powershell.*-encodedcommand\s+")
            .base_score(10)
            .cwe(78)
            .tags(&["cmdi", "windows", "powershell"])
            .build()?,

        RuleBuilder::new(932123, "Command Injection: Windows net command")
            .description("Detects Windows net user/localgroup commands")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\bnet\s+(user|localgroup|group|share|view)\b")
            .base_score(8)
            .cwe(78)
            .tags(&["cmdi", "windows"])
            .build()?,

        RuleBuilder::new(932124, "Command Injection: Windows wmic")
            .description("Detects Windows wmic commands")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\bwmic\s+(process|os|computersystem|useraccount)")
            .base_score(8)
            .cwe(78)
            .tags(&["cmdi", "windows"])
            .build()?,

        // Environment variable injection
        RuleBuilder::new(932130, "Command Injection: Environment variable")
            .description("Detects environment variable expansion attacks")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Medium)
            .confidence(Confidence::Medium)
            .paranoia(2)
            .pattern(r"(?i)\$\{[A-Z_][A-Z0-9_]*\}")
            .base_score(5)
            .cwe(78)
            .tags(&["cmdi", "env"])
            .build()?,

        RuleBuilder::new(932131, "Command Injection: IFS manipulation")
            .description("Detects IFS environment variable manipulation")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(2)
            .pattern(r"(?i)IFS\s*=")
            .base_score(8)
            .cwe(78)
            .tags(&["cmdi", "unix", "env"])
            .build()?,

        // Dangerous commands
        RuleBuilder::new(932140, "Command Injection: rm -rf")
            .description("Detects destructive rm command")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::Critical)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\brm\s+(-rf|-fr|--recursive)")
            .base_score(10)
            .cwe(78)
            .tags(&["cmdi", "unix", "destructive"])
            .build()?,

        RuleBuilder::new(932141, "Command Injection: chmod 777")
            .description("Detects dangerous chmod commands")
            .attack_type(AttackType::CommandInjection)
            .severity(Severity::High)
            .confidence(Confidence::High)
            .paranoia(1)
            .pattern(r"(?i)\bchmod\s+[0-7]?777\b")
            .base_score(8)
            .cwe(78)
            .tags(&["cmdi", "unix"])
            .build()?,
    ];

    Ok(all_rules
        .into_iter()
        .filter(|r| r.paranoia_level <= paranoia_level)
        .collect())
}
