//! Integration tests for pyneat-rs security rules.

use pyneat_rs::{all_security_rules, Rule};

/// Test that all security rules can be instantiated and have valid IDs.
#[test]
fn test_all_rules_have_valid_ids() {
    let rules = all_security_rules();
    assert!(!rules.is_empty(), "Should have at least some rules");

    for rule in &rules {
        let id = rule.id();
        assert!(
            !id.is_empty(),
            "Rule should have a non-empty ID"
        );
        assert!(
            id.len() <= 20,
            "Rule ID '{}' seems too long",
            id
        );
    }
}

/// Test that all rules have non-empty names.
#[test]
fn test_all_rules_have_valid_names() {
    let rules = all_security_rules();

    for rule in &rules {
        let name = rule.name();
        assert!(
            !name.is_empty(),
            "Rule {} should have a non-empty name",
            rule.id()
        );
    }
}

/// Test that rule IDs are unique across all rules.
#[test]
fn test_rule_ids_are_unique() {
    let rules = all_security_rules();
    let mut ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
    ids.sort();
    ids.dedup();

    assert_eq!(
        ids.len(),
        rules.len(),
        "All rule IDs should be unique"
    );
}

/// Test that we have a reasonable number of rules.
#[test]
fn test_minimum_rule_count() {
    let rules = all_security_rules();
    // We should have at least 50 rules after the refactor
    assert!(
        rules.len() >= 50,
        "Should have at least 50 rules, found {}",
        rules.len()
    );
}

/// Test that PHP rules are registered.
#[test]
fn test_php_rules_exist() {
    let rules = all_security_rules();

    // PHP rules should be in the range SEC-073 to SEC-090
    let php_rules: Vec<_> = rules.iter()
        .filter(|r| {
            let id = r.id();
            id.starts_with("SEC-07") || id.starts_with("SEC-08") || id.starts_with("SEC-09")
        })
        .collect();

    assert!(
        php_rules.len() >= 10,
        "Should have at least 10 PHP rules, found {}",
        php_rules.len()
    );
}

/// Test that all rules report their severity.
#[test]
fn test_all_rules_have_severity() {
    let rules = all_security_rules();

    for rule in &rules {
        let severity = rule.severity();
        assert!(
            !format!("{:?}", severity).is_empty(),
            "Rule {} should have a valid severity",
            rule.id()
        );
    }
}
