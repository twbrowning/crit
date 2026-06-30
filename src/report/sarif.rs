//! SARIF 2.1.0 output for CI / GitHub code-scanning integration.

use crate::finding::Finding;
use crate::rule::Rule;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Render findings as a SARIF 2.1.0 log. `rules` supplies rule metadata for the
/// `tool.driver.rules` section; any rule that produced a finding is included.
pub fn render_sarif(findings: &[Finding], rules: &[Rule]) -> String {
    let rule_by_id: BTreeMap<&str, &Rule> = rules.iter().map(|r| (r.id.as_str(), r)).collect();

    // Stable, de-duplicated list of rules that actually fired, with a SARIF
    // ruleIndex assigned by first appearance.
    let mut rule_index: BTreeMap<&str, usize> = BTreeMap::new();
    let mut driver_rules: Vec<Value> = Vec::new();
    for f in findings {
        if rule_index.contains_key(f.rule_id.as_str()) {
            continue;
        }
        let idx = driver_rules.len();
        rule_index.insert(f.rule_id.as_str(), idx);
        driver_rules.push(rule_descriptor(&f.rule_id, rule_by_id.get(f.rule_id.as_str()).copied()));
    }

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id.as_str()],
                "level": f.severity.sarif_level(),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri(&f.file) },
                        "region": {
                            "startLine": f.start.line,
                            "startColumn": f.start.column,
                            "endLine": f.end.line,
                            "endColumn": f.end.column,
                            "snippet": { "text": f.snippet }
                        }
                    }
                }],
                "properties": { "language": f.language }
            })
        })
        .collect();

    let log = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "catseye",
                    "informationUri": "https://github.com/twbrowning/catseye",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": driver_rules
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&log).expect("SARIF serializes")
}

fn rule_descriptor(id: &str, rule: Option<&Rule>) -> Value {
    let mut desc = json!({ "id": id });
    let obj = desc.as_object_mut().unwrap();
    if let Some(r) = rule {
        if let Some(name) = &r.name {
            obj.insert("name".into(), json!(name));
        }
        obj.insert(
            "shortDescription".into(),
            json!({ "text": r.message }),
        );
        if let Some(d) = &r.description {
            obj.insert("fullDescription".into(), json!({ "text": d }));
        }
        obj.insert(
            "defaultConfiguration".into(),
            json!({ "level": r.severity.sarif_level() }),
        );
        let mut props = serde_json::Map::new();
        if let Some(cwe) = &r.cwe {
            props.insert("cwe".into(), json!(cwe));
        }
        if !r.references.is_empty() {
            props.insert("references".into(), json!(r.references));
        }
        if !props.is_empty() {
            obj.insert("properties".into(), Value::Object(props));
        }
        if let Some(help) = &r.description {
            obj.insert("help".into(), json!({ "text": help }));
        }
    }
    desc
}

/// SARIF artifact URIs use forward slashes and are relative where possible.
fn uri(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
