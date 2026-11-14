//! The workspace charter, read from one `cargo metadata`: no relift crate
//! anywhere in the graph, every member inherits the workspace lints (so
//! `unsafe_code = "forbid"` reaches all of them), and the bands hold:
//! switch-io depends on no member, switch-formats only on switch-io, and
//! switch-tools sits on top. Each absence rule has a presence control so a
//! broken walk cannot pass by seeing nothing.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

struct Graph {
    names: BTreeMap<String, String>,
    deps: BTreeMap<String, Vec<String>>,
    members: Vec<String>,
    manifests: BTreeMap<String, String>,
}

fn graph() -> Graph {
    let out = switch_io::command(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata runs");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("metadata is JSON");
    let mut names = BTreeMap::new();
    let mut manifests = BTreeMap::new();
    for p in v["packages"].as_array().expect("packages") {
        let id = p["id"].as_str().expect("id").to_string();
        names.insert(id.clone(), p["name"].as_str().expect("name").to_string());
        manifests.insert(id, p["manifest_path"].as_str().expect("path").to_string());
    }
    let mut deps = BTreeMap::new();
    for n in v["resolve"]["nodes"].as_array().expect("resolve nodes") {
        let id = n["id"].as_str().expect("id").to_string();
        let d = n["dependencies"]
            .as_array()
            .expect("dependencies")
            .iter()
            .map(|d| d.as_str().expect("dep id").to_string())
            .collect();
        deps.insert(id, d);
    }
    let members = v["workspace_members"]
        .as_array()
        .expect("members")
        .iter()
        .map(|m| m.as_str().expect("member id").to_string())
        .collect();
    Graph {
        names,
        deps,
        members,
        manifests,
    }
}

impl Graph {
    fn id(&self, name: &str) -> String {
        self.names
            .iter()
            .find(|(_, n)| *n == name)
            .map(|(id, _)| id.clone())
            .unwrap_or_else(|| panic!("{name} is not in the graph"))
    }

    /// Every crate `name` reaches (normal, build and dev edges).
    fn closure(&self, name: &str) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![self.id(name)];
        while let Some(id) = stack.pop() {
            for d in self.deps.get(&id).into_iter().flatten() {
                if seen.insert(d.clone()) {
                    stack.push(d.clone());
                }
            }
        }
        seen.iter().map(|id| self.names[id].clone()).collect()
    }

    fn member_names(&self) -> Vec<String> {
        self.members.iter().map(|m| self.names[m].clone()).collect()
    }
}

#[test]
fn no_relift_crate_in_the_graph() {
    let g = graph();
    let all: Vec<&String> = g.names.values().collect();
    assert!(
        all.iter().any(|n| *n == "switch-formats"),
        "presence control"
    );
    let relift: Vec<&&String> = all.iter().filter(|n| n.starts_with("relift")).collect();
    assert!(relift.is_empty(), "relift crates in the graph: {relift:?}");
}

#[test]
fn every_member_inherits_the_workspace_lints() {
    let g = graph();
    let mut names = g.member_names();
    names.sort();
    assert_eq!(names, ["switch-formats", "switch-io", "switch-tools"]);
    for m in &g.members {
        let text = std::fs::read_to_string(&g.manifests[m]).expect("manifest reads");
        let t: toml::Table = toml::from_str(&text).expect("manifest parses");
        let inherits = t
            .get("lints")
            .and_then(|l| l.get("workspace"))
            .and_then(toml::Value::as_bool);
        assert_eq!(
            inherits,
            Some(true),
            "{} lacks [lints] workspace = true",
            g.names[m]
        );
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
    let t: toml::Table =
        toml::from_str(&std::fs::read_to_string(root).expect("root manifest")).expect("parses");
    assert_eq!(
        t["workspace"]["lints"]["rust"]["unsafe_code"].as_str(),
        Some("forbid")
    );
}

#[test]
fn the_bands_hold() {
    let g = graph();
    let members: BTreeSet<String> = g.member_names().into_iter().collect();
    let inner = |name: &str| -> BTreeSet<String> {
        g.closure(name).intersection(&members).cloned().collect()
    };
    assert!(inner("switch-io").is_empty(), "{:?}", inner("switch-io"));
    assert_eq!(
        inner("switch-formats"),
        BTreeSet::from(["switch-io".to_string()])
    );
    assert!(
        inner("switch-tools").contains("switch-formats"),
        "presence control"
    );
    assert!(
        !g.closure("switch-formats").contains("clap"),
        "formats stay CLI free"
    );
    assert!(
        g.closure("switch-tools").contains("clap"),
        "presence control"
    );
}
