//! PyNeat Rust Security Scanner
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU Affero General Public License as published
//! by the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//! GNU Affero General Public License for more details.
//!
//! You should have received a copy of the GNU Affero General Public License
//! along with this program. If not, see <https://www.gnu.org/licenses/>.

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
