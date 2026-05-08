//! Worklist-based taint propagation engine.
//!
//! The engine performs intra-procedural data flow analysis using a worklist algorithm.

#[allow(dead_code)]

use std::collections::HashMap;

use crate::scanner::ln_ast::LnAst;
use crate::scanner::taint::labels::{
    SinkPosition, TaintLabel, TaintPropagator, TaintRule,
    TaintSanitizer, TaintSink, TaintSource,
};
use crate::scanner::taint::dfg::{DataFlowGraph, DfgNodeId, DfgNodeKind};

/// Extract potential variable/property names from arbitrary text.
fn extract_identifiers_from_text(text: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = String::new();
    let mut in_ident = false;

    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            current.push(ch);
            in_ident = true;
        } else {
            if in_ident && !current.is_empty() && current.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false) {
                // Skip Python keywords and common builtins that are unlikely to be tainted sources
                match current.as_str() {
                    "if" | "else" | "for" | "while" | "def" | "class" | "return"
                    | "import" | "from" | "as" | "in" | "not" | "and" | "or"
                    | "None" | "True" | "False" => {}
                    _ => {
                        if current.len() > 1 && current.len() < 64 {
                            results.push(current.clone());
                        }
                    }
                }
            }
            current.clear();
            in_ident = false;
        }
    }

    // Handle trailing identifier
    if in_ident && !current.is_empty() && current.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false) {
        match current.as_str() {
            "if" | "else" | "for" | "while" | "def" | "class" | "return"
            | "import" | "from" | "as" | "in" | "not" | "and" | "or"
            | "None" | "True" | "False" => {}
            _ => {
                if current.len() > 1 && current.len() < 64 {
                    results.push(current.clone());
                }
            }
        }
    }

    results
}

/// A finding from taint analysis with a full trace.
#[derive(Debug, Clone)]
pub struct TaintFinding {
    pub rule_id: String,
    pub severity: String,
    pub line: usize,
    pub column: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub snippet: String,
    pub problem: String,
    pub labels: Vec<TaintLabel>,
    pub trace: Vec<TaintTraceNode>,
    pub replacement: String,
}

impl TaintFinding {
    fn new(
        rule_id: &str,
        severity: &str,
        node: &crate::scanner::taint::dfg::DfgNode,
        problem: &str,
        labels: Vec<TaintLabel>,
    ) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            severity: severity.to_string(),
            line: node.line,
            column: node.column,
            start_byte: node.start_byte,
            end_byte: node.end_byte,
            snippet: node.display_name(),
            problem: problem.to_string(),
            labels,
            trace: Vec::new(),
            replacement: String::new(),
        }
    }
}

/// A single node in the taint trace.
#[derive(Debug, Clone)]
pub struct TaintTraceNode {
    pub kind: String,
    pub description: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
}

impl TaintTraceNode {
    fn new(kind: &str, node: &crate::scanner::taint::dfg::DfgNode, description: &str) -> Self {
        Self {
            kind: kind.to_string(),
            description: description.to_string(),
            line: node.line,
            column: node.column,
            snippet: node.display_name(),
        }
    }
}

/// Configuration for a taint analysis run.
#[derive(Debug, Clone)]
pub struct TaintConfig {
    pub max_nodes: usize,
    pub max_trace_length: usize,
    pub timeout_ms: Option<u64>,
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            max_nodes: 10_000,
            max_trace_length: 50,
            timeout_ms: None,
        }
    }
}

/// The taint analysis engine.
pub struct TaintEngine<'a> {
    #[allow(dead_code)]
    code: &'a str,
    config: TaintConfig,
    rules: Vec<Box<dyn TaintRule>>,
    sources: Vec<TaintSource>,
    sinks: Vec<TaintSink>,
    sanitizers: Vec<TaintSanitizer>,
    propagators: Vec<TaintPropagator>,
    dfg: DataFlowGraph,
    worklist: Vec<DfgNodeId>,
    findings: Vec<TaintFinding>,
    var_nodes: HashMap<String, Vec<DfgNodeId>>,
}

impl<'a> TaintEngine<'a> {
    pub fn new(code: &'a str) -> Self {
        Self {
            code,
            config: TaintConfig::default(),
            rules: Vec::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: Vec::new(),
            propagators: Vec::new(),
            dfg: DataFlowGraph::new(),
            worklist: Vec::new(),
            findings: Vec::new(),
            var_nodes: HashMap::new(),
        }
    }

    pub fn with_config(mut self, config: TaintConfig) -> Self {
        self.config = config;
        self
    }

    pub fn add_rule(&mut self, rule: Box<dyn TaintRule>) {
        self.sources.extend(rule.sources());
        self.sinks.extend(rule.sinks());
        self.sanitizers.extend(rule.sanitizers());
        self.propagators.extend(rule.propagators());
        self.rules.push(rule);
    }

    /// Build the DFG from an LnAst and run analysis.
    pub fn analyze_with_ast(&mut self, ast: &LnAst) {
        self.build_dfg(ast);
        self.analyze();
    }

    fn build_dfg(&mut self, ast: &LnAst) {
        // First pass: register all variable definitions (assignments)
        for assignment in &ast.assignments {
            let rhs_id = self.dfg.add_node_full(
                DfgNodeKind::Variable(assignment.value.clone().unwrap_or_default()),
                assignment.start_line,
                0,
                0,
                0,
            );
            let node_id = self.dfg.add_node_full(
                DfgNodeKind::Assignment {
                    target: assignment.name.clone(),
                    rhs: rhs_id,
                },
                assignment.start_line,
                0,
                0,
                0,
            );
            self.dfg.add_edge(rhs_id, node_id);
            self.var_nodes
                .entry(assignment.name.clone())
                .or_default()
                .push(node_id);

            // Extract variable names referenced in the RHS value text.
            // E.g., for `query = "SELECT * FROM " + table + " WHERE id = " + uid`,
            // extract "table" and "uid" so they get registered as nodes.
            let rhs_text = assignment.value.as_deref().unwrap_or("");
            for var_name in extract_identifiers_from_text(rhs_text) {
                let var_id = self.dfg.add_node_full(
                    DfgNodeKind::Variable(var_name.clone()),
                    assignment.start_line,
                    0,
                    0,
                    0,
                );
                self.var_nodes
                    .entry(var_name)
                    .or_default()
                    .push(var_id);
            }
        }

        // Second pass: register function calls
        for call in &ast.calls {
            let args: Vec<DfgNodeId> = call
                .arguments
                .iter()
                .map(|arg_text| {
                    let var_id = self.dfg.add_node_full(
                        DfgNodeKind::Variable(arg_text.clone()),
                        call.start_line,
                        0,
                        0,
                        0,
                    );
                    // Also register the arg text as a variable name for propagation
                    self.var_nodes
                        .entry(arg_text.clone())
                        .or_default()
                        .push(var_id);
                    var_id
                })
                .collect();

            let call_node = self.dfg.add_node_full(
                DfgNodeKind::Call {
                    callee: call.callee.clone(),
                    args: args.clone(),
                },
                call.start_line,
                0,
                0,
                0,
            );

            for arg_id in &args {
                self.dfg.add_edge(*arg_id, call_node);
            }
        }

        // Third pass: register identifiers (function parameters, etc.)
        for id in &ast.identifiers {
            if id.is_definition {
                let node_id = self.dfg.add_node_full(
                    DfgNodeKind::Variable(id.name.clone()),
                    id.start_line,
                    0,
                    id.start_byte,
                    id.end_byte,
                );
                self.var_nodes
                    .entry(id.name.clone())
                    .or_default()
                    .push(node_id);
            }
        }
    }

    fn get_source_label(&self, callee: &str) -> Option<TaintLabel> {
        for source in &self.sources {
            if source.matches_call(callee) {
                return Some(source.label.clone());
            }
        }
        None
    }




    #[allow(dead_code)]
    fn get_matching_sink(&self, callee: &str) -> Option<&TaintSink> {
        for sink in &self.sinks {
            if sink.matches_callee(callee) {
                return Some(sink);
            }
        }
        None
    }

    fn get_matching_propagator(&self, callee: &str) -> Option<&TaintPropagator> {
        for prop in &self.propagators {
            if prop.matches_callee(callee) {
                return Some(prop);
            }
        }
        None
    }

    fn matches_sanitizer(&self, text: &str) -> bool {
        self.sanitizers.iter().any(|s| s.matches(text))
    }

    fn mark_tainted(&mut self, node_id: DfgNodeId, label: TaintLabel) {
        if let Some(node) = self.dfg.node_mut(node_id) {
            if node.sanitized {
                return;
            }
            if node.taint.insert(label) {
                self.worklist.push(node_id);
            }
        }
    }

    fn is_tainted(&self, node_id: DfgNodeId) -> bool {
        self.dfg.node(node_id).map(|n| n.is_tainted()).unwrap_or(false)
    }

    fn get_taint_labels(&self, node_id: DfgNodeId) -> Vec<TaintLabel> {
        self.dfg
            .node(node_id)
            .map(|n| n.taint.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn analyze(&mut self) {
        self.seed_sources();

        while let Some(node_id) = self.worklist.pop() {
            if self.dfg.len() > self.config.max_nodes {
                break;
            }
            self.process_node(node_id);
        }

        self.check_sinks();
    }

    fn seed_sources(&mut self) {
        let ids: Vec<DfgNodeId> = self.dfg.node_ids();
        for node_id in ids {
            let node = match self.dfg.node(node_id) {
                Some(n) => n.clone(),
                None => continue,
            };

            match &node.kind {
                DfgNodeKind::Call { callee, .. } => {
                    if let Some(label) = self.get_source_label(callee) {
                        self.mark_tainted(node_id, label);
                    }
                }
                DfgNodeKind::Variable(name) => {
                    // Standard identifier check
                    if self.sources.iter().any(|s| s.matches_identifier(name)) {
                        self.mark_tainted(node_id, TaintLabel::Tainted);
                    }
                    // Also check if this identifier is actually a method call result
                    // (happens when the AST parser extracts full expression text as identifier)
                    if name.contains('(') {
                        if let Some(label) = self.get_source_label(name) {
                            self.mark_tainted(node_id, label);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn process_node(&mut self, node_id: DfgNodeId) {
        let node = match self.dfg.node(node_id) {
            Some(n) => n.clone(),
            None => return,
        };

        match &node.kind {
            DfgNodeKind::Assignment { target, .. } => {
                // Find all references to this variable and propagate taint
                let var_ids: Vec<DfgNodeId> = self.dfg.node_ids();
                for vid in var_ids {
                    if let Some(n) = self.dfg.node(vid) {
                        if let DfgNodeKind::Variable(v) = &n.kind {
                            if v == target && self.is_tainted(node_id) {
                                for label in self.get_taint_labels(node_id) {
                                    self.mark_tainted(vid, label);
                                }
                            }
                        }
                    }
                }
            }
            DfgNodeKind::Call { callee, args } => {
                if let Some(_prop) = self.get_matching_propagator(callee) {
                    for arg_id in args {
                        if self.is_tainted(*arg_id) {
                            let ret_node = self.dfg.add_node_full(
                                DfgNodeKind::Call {
                                    callee: callee.clone(),
                                    args: args.clone(),
                                },
                                node.line,
                                0,
                                0,
                                0,
                            );
                            for label in self.get_taint_labels(*arg_id) {
                                self.mark_tainted(ret_node, label);
                            }
                            self.dfg.add_edge(*arg_id, ret_node);
                        }
                    }
                } else {
                    for arg_id in args {
                        if self.is_tainted(*arg_id) {
                            for label in self.get_taint_labels(*arg_id) {
                                self.mark_tainted(node_id, label);
                            }
                            break;
                        }
                    }
                }
            }
            DfgNodeKind::Operation { op: _, operands } => {
                for operand_id in operands {
                    if self.is_tainted(*operand_id) {
                        for label in self.get_taint_labels(*operand_id) {
                            self.mark_tainted(node_id, label);
                        }
                        break;
                    }
                }
            }
            DfgNodeKind::FieldAccess { base, .. } | DfgNodeKind::IndexAccess { base, .. } => {
                if self.is_tainted(*base) {
                    for label in self.get_taint_labels(*base) {
                        self.mark_tainted(node_id, label);
                    }
                }
            }
            DfgNodeKind::Variable(name) => {
                let def_ids: Vec<DfgNodeId> = self.var_nodes.get(name).cloned().unwrap_or_default();
                for def_id in def_ids {
                    if self.is_tainted(def_id) {
                        for label in self.get_taint_labels(def_id) {
                            self.mark_tainted(node_id, label);
                        }
                    }
                }
            }
            DfgNodeKind::Constant | DfgNodeKind::Parameter(_) | DfgNodeKind::Unknown => {}
        }

        // Edge propagation
        let succ_ids: Vec<DfgNodeId> = self.dfg.successors(node_id);
        let node_labels = self.get_taint_labels(node_id);
        for succ_id in succ_ids {
            let succ_name = self.dfg.node(succ_id).map(|n| n.display_name()).unwrap_or_default();
            if !self.is_tainted(succ_id) && !self.matches_sanitizer(&succ_name) {
                for label in &node_labels {
                    self.mark_tainted(succ_id, label.clone());
                }
            }
        }
    }

    fn check_sinks(&mut self) {
        let ids: Vec<DfgNodeId> = self.dfg.node_ids();
        for node_id in ids {
            let node = match self.dfg.node(node_id) {
                Some(n) => n.clone(),
                None => continue,
            };

            let DfgNodeKind::Call { callee, args } = &node.kind else {
                continue;
            };

            for sink in &self.sinks {
                if !sink.matches_callee(callee) {
                    continue;
                }

                let tainted_args: Vec<(usize, TaintLabel)> = match &sink.sink_arg {
                    SinkPosition::Entire => args
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| {
                            let arg_id = *args.get(*i).unwrap_or(&DfgNodeId(0));
                            self.is_tainted(arg_id) || self.arg_contains_tainted_var(arg_id)
                        })
                        .flat_map(|(i, _)| {
                            self.get_taint_labels_for_arg(*args.get(i).unwrap_or(&DfgNodeId(0)))
                                .into_iter()
                                .filter(|l| sink.accepts_taint(l))
                                .map(|l| (i, l))
                                .collect::<Vec<_>>()
                        })
                        .collect(),
                    SinkPosition::Argument(idx) => {
                        if *idx < args.len() {
                            let arg_id = *args.get(*idx).unwrap_or(&DfgNodeId(0));
                            if self.is_tainted(arg_id) || self.arg_contains_tainted_var(arg_id) {
                                self.get_taint_labels_for_arg(arg_id)
                                    .into_iter()
                                    .filter(|l| sink.accepts_taint(l))
                                    .map(|l| (*idx, l))
                                    .collect()
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                    _ => continue,
                };

                if !tainted_args.is_empty() {
                    let labels: Vec<TaintLabel> = tainted_args.iter().map(|(_, l)| l.clone()).collect();
                    let mut finding = TaintFinding::new(&sink.rule_id, &sink.severity, &node, &sink.description, labels);
                    finding.trace = self.build_trace_for_sink(node_id, &tainted_args);
                    self.findings.push(finding);
                }
            }
        }
    }

    /// Build a trace from sources to a sink by following variable definitions.
    fn build_trace_for_sink(&self, sink_id: DfgNodeId, tainted_args: &[(usize, TaintLabel)]) -> Vec<TaintTraceNode> {
        let mut trace = Vec::new();
        let mut visited = std::collections::HashSet::new();

        // For each tainted argument, trace back to its source
        for (arg_idx, _label) in tainted_args {
            let arg_text = match self.dfg.node(DfgNodeId(*arg_idx)) {
                Some(n) => n.display_name(),
                None => continue,
            };
            // Try to find the variable reference in the arg text
            for var_name in extract_identifiers_from_text(&arg_text) {
                self.trace_var(&var_name, &mut trace, &mut visited, 0);
            }
        }

        // Also add the sink itself to the trace
        if let Some(sink_node) = self.dfg.node(sink_id) {
            if !visited.contains(&sink_id) {
                visited.insert(sink_id);
                trace.push(TaintTraceNode::new("sink", sink_node, &sink_node.display_name()));
            }
        }

        trace.reverse();
        trace
    }

    /// Trace a variable back to its source.
    fn trace_var(&self, var_name: &str, trace: &mut Vec<TaintTraceNode>, visited: &mut std::collections::HashSet<DfgNodeId>, depth: usize) {
        if depth > self.config.max_trace_length {
            return;
        }

        // Find all definitions of this variable
        let Some(def_ids) = self.var_nodes.get(var_name) else {
            return;
        };

        for def_id in def_ids {
            if visited.contains(def_id) {
                continue;
            }

            let Some(def_node) = self.dfg.node(*def_id) else {
                continue;
            };

            visited.insert(*def_id);

            match &def_node.kind {
                DfgNodeKind::Call { callee, .. } => {
                    // Check if this call is a source
                    let is_source = self.sources.iter().any(|s| s.matches_call(callee));
                    if is_source {
                        trace.push(TaintTraceNode::new("source", def_node, &def_node.display_name()));
                    } else {
                        trace.push(TaintTraceNode::new("propagate", def_node, &def_node.display_name()));
                        // Continue tracing arguments of this call
                        if let Some(call_node) = self.dfg.node(*def_id) {
                            if let DfgNodeKind::Call { args, .. } = &call_node.kind {
                                for arg_id in args {
                                    let arg_text = self.dfg.node(*arg_id).map(|n| n.display_name()).unwrap_or_default();
                                    for inner_var in extract_identifiers_from_text(&arg_text) {
                                        self.trace_var(&inner_var, trace, visited, depth + 1);
                                    }
                                }
                            }
                        }
                    }
                }
                DfgNodeKind::Variable(v) => {
                    trace.push(TaintTraceNode::new("propagate", def_node, &def_node.display_name()));
                    // Trace the definition of this variable
                    self.trace_var(v, trace, visited, depth + 1);
                }
                DfgNodeKind::Assignment { target, .. } => {
                    trace.push(TaintTraceNode::new("propagate", def_node, &format!("{} = ...", target)));
                    // The RHS of the assignment was already traced via var_nodes
                }
                _ => {
                    trace.push(TaintTraceNode::new("propagate", def_node, &def_node.display_name()));
                }
            }
        }
    }

    /// Check if an argument's text contains references to any tainted variable.
    fn arg_contains_tainted_var(&self, arg_id: DfgNodeId) -> bool {
        let arg_text = match self.dfg.node(arg_id) {
            Some(n) => n.display_name(),
            None => return false,
        };
        // Skip pure string literals (constants) — no variable interpolation
        if (arg_text.starts_with('"') || arg_text.starts_with('\''))
            && !arg_text.contains('+')
            && !arg_text.contains("..")
        {
            return false;
        }
        // Check each referenced variable in the text
        for var_name in extract_identifiers_from_text(&arg_text) {
            if let Some(var_ids) = self.var_nodes.get(&var_name) {
                for vid in var_ids {
                    if self.is_tainted(*vid) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Get taint labels for an argument, including from embedded tainted variable references.
    fn get_taint_labels_for_arg(&self, arg_id: DfgNodeId) -> Vec<TaintLabel> {
        let mut labels = self.get_taint_labels(arg_id);
        let arg_text = match self.dfg.node(arg_id) {
            Some(n) => n.display_name(),
            None => return labels,
        };
        if (arg_text.starts_with('"') || arg_text.starts_with('\''))
            && !arg_text.contains('+')
            && !arg_text.contains("..")
        {
            return labels;
        }
        for var_name in extract_identifiers_from_text(&arg_text) {
            if let Some(var_ids) = self.var_nodes.get(&var_name) {
                for vid in var_ids {
                    if self.is_tainted(*vid) {
                        for label in self.get_taint_labels(*vid) {
                            if !labels.contains(&label) {
                                labels.push(label);
                            }
                        }
                    }
                }
            }
        }
        labels
    }

    pub fn findings(&self) -> &[TaintFinding] {
        &self.findings
    }

    pub fn dfg(&self) -> &DataFlowGraph {
        &self.dfg
    }

    pub fn node_count(&self) -> usize {
        self.dfg.len()
    }

    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    pub fn sink_count(&self) -> usize {
        self.sinks.len()
    }

    pub fn findings_vec(&self) -> Vec<&TaintFinding> {
        self.findings.iter().collect()
    }
}
