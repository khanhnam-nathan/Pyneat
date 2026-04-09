//! Integration tests for pyneat-rs.

use crate::scanner::tree_sitter::parse;
use crate::rules::security::{
    CommandInjectionRule, DeserializationRceRule, EvalExecRule, PathTraversalRule, SqlInjectionRule,
};
use crate::rules::Rule;

#[test]
fn test_command_injection() {
    let rule = CommandInjectionRule;
    let code = r#"
import os
os.system("ls -la")
"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].rule_id, "SEC-001");
}

#[test]
fn test_sql_injection() {
    let rule = SqlInjectionRule;
    let code = r#"cursor.execute("SELECT * FROM users WHERE id=" + user_id)"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].rule_id, "SEC-002");
}

#[test]
fn test_eval_usage() {
    let rule = EvalExecRule;
    let code = "result = eval(user_input)";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].rule_id, "SEC-003");
}

#[test]
fn test_yaml_unsafe_load() {
    let rule = DeserializationRceRule;
    let code = "data = yaml.load(user_yaml)";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].rule_id, "SEC-004");
    assert!(findings[0].auto_fix_available);
}

#[test]
fn test_yaml_safe_load_auto_fix() {
    let rule = DeserializationRceRule;
    let code = "data = yaml.load(user_yaml)";
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    if let Some(fix) = rule.fix(&findings[0], code) {
        assert!(fix.replacement.contains("safe_load"));
    }
}

#[test]
fn test_path_traversal() {
    let rule = PathTraversalRule;
    let code = r#"
with open(user_filename) as f:
    content = f.read()
"#;
    let tree = parse(code).unwrap();
    let findings = rule.detect(&tree, code);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].rule_id, "SEC-005");
}

#[test]
fn test_parse_simple_code() {
    let code = "x = 1";
    let tree = parse(code).expect("Failed to parse");
    assert_eq!(tree.root_node().kind(), "module");
}

#[test]
fn test_parse_with_function() {
    let code = r#"
def hello():
    print("Hello, World!")
"#;
    let tree = parse(code).expect("Failed to parse");
    assert_eq!(tree.root_node().kind(), "module");
}
