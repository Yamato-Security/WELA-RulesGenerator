use csv::ReaderBuilder;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::write;
use std::{env, fs};
use walkdir::WalkDir;
use yaml_rust2::{Yaml, YamlLoader};

enum Channel {
    Security,
    PowerShell,
    Other(String),
}

impl Display for Channel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Channel::Security => write!(f, "sec"),
            Channel::PowerShell => write!(f, "pwsh"),
            Channel::Other(name) => write!(f, "{}", name),
        }
    }
}

fn list_yml_files(dir: &str) -> Vec<String> {
    let mut yml_files = Vec::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file()
            && path.extension().and_then(|ext| ext.to_str()) == Some("yml")
            && let Some(path_str) = path.to_str()
        {
            yml_files.push(path_str.to_string());
        }
    }

    yml_files
}

fn extract_event_ids(yaml: &Yaml, event_ids: &mut HashSet<String>) {
    match yaml {
        Yaml::Hash(hash) => {
            for (key, value) in hash {
                if key.as_str() == Some("EventID") {
                    match value {
                        Yaml::Array(ids) => {
                            for id in ids {
                                if let Some(id) = id.as_i64() {
                                    event_ids.insert(id.to_string());
                                } else if let Some(id) = id.as_str() {
                                    event_ids.insert(id.to_string());
                                }
                            }
                        }
                        Yaml::String(id) => {
                            event_ids.insert(id.clone());
                        }
                        Yaml::Integer(id) => {
                            event_ids.insert(id.to_string());
                        }
                        _ => {}
                    }
                } else {
                    extract_event_ids(value, event_ids);
                }
            }
        }
        Yaml::Array(array) => {
            for item in array {
                extract_event_ids(item, event_ids);
            }
        }
        _ => {}
    }
}

fn contains_builtin_channel(yaml: &Yaml) -> Option<Vec<Channel>> {
    fn check_channel(value: &Yaml) -> Option<Channel> {
        match value.as_str() {
            Some("Security") => Some(Channel::Security),
            Some("Microsoft-Windows-PowerShell/Operational")
            | Some("PowerShellCore/Operational")
            | Some("Windows PowerShell") => Some(Channel::PowerShell),
            val => Some(Channel::Other(val?.to_string())),
        }
    }

    match yaml {
        Yaml::Hash(hash) => {
            for (key, value) in hash {
                if key.as_str() == Some("Channel") {
                    match value {
                        Yaml::Array(array) => {
                            let mut channels = Vec::new();
                            for item in array {
                                if let Some(channel) = check_channel(item) {
                                    channels.push(channel);
                                }
                            }
                            if !channels.is_empty() {
                                return Some(channels);
                            }
                        }
                        Yaml::String(_) => {
                            if let Some(channel) = check_channel(value) {
                                return Some(vec![channel]);
                            }
                        }
                        _ => {}
                    }
                } else if let Some(channel) = contains_builtin_channel(value) {
                    return Some(channel);
                }
            }
        }
        Yaml::Array(array) => {
            for item in array {
                if let Some(channel) = contains_builtin_channel(item) {
                    return Some(channel);
                }
            }
        }
        _ => {}
    }
    None
}

/// Maps a Sigma `attack.<tactic>` tag to its ATT&CK tactic ID.
///
/// ATT&CK v19 (2026-04-28) split Defense Evasion into Stealth (TA0005, which kept the
/// old ID) and Defense Impairment (TA0112). `attack.defense-evasion` is kept so rules
/// that have not been retagged yet still resolve.
fn tactic_id(tag: &str) -> Option<&'static str> {
    match tag {
        "attack.reconnaissance" => Some("TA0043"),
        "attack.resource-development" => Some("TA0042"),
        "attack.initial-access" => Some("TA0001"),
        "attack.execution" => Some("TA0002"),
        "attack.persistence" => Some("TA0003"),
        "attack.privilege-escalation" => Some("TA0004"),
        "attack.stealth" | "attack.defense-evasion" => Some("TA0005"),
        "attack.credential-access" => Some("TA0006"),
        "attack.discovery" => Some("TA0007"),
        "attack.lateral-movement" => Some("TA0008"),
        "attack.collection" => Some("TA0009"),
        "attack.exfiltration" => Some("TA0010"),
        "attack.command-and-control" => Some("TA0011"),
        "attack.impact" => Some("TA0040"),
        "attack.defense-impairment" => Some("TA0112"),
        _ => None,
    }
}

/// Normalizes one Sigma tag: tactics become `TA####`, techniques become `T####[.###]`.
/// Every other tag (`attack.s0183`, `cve.2025-53770`, `car.2013-05-002`, ...) is passed
/// through unchanged.
fn normalize_tag(tag: &str) -> String {
    if let Some(id) = tactic_id(tag) {
        return id.to_string();
    }
    if let Some(rest) = tag.strip_prefix("attack.t") {
        return format!("T{rest}");
    }
    tag.to_string()
}

/// Reports `attack.*` tags that survived normalization without becoming a known ATT&CK
/// reference. These are almost always typos in the rule (hayabusa-rules has shipped
/// `attack.1136.001` and `attack.11136.001` for `attack.t1136.001`), which silently
/// costs the rule its place in the ATT&CK Navigator heatmap.
fn suspicious_attack_tag(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix("attack.") else {
        return false;
    };
    // s0183 = software, g0010 = group, c0028 = campaign, ds0005 = data source.
    let known_prefix = ["s", "g", "c", "ds", "m"]
        .iter()
        .filter_map(|p| rest.strip_prefix(*p))
        .any(|digits| !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()));
    !known_prefix
}

fn parse_yaml(doc: Yaml, eid_subcategory_pair: &Vec<(String, String)>) -> Option<Value> {
    let sysmon_tag = doc["tags"]
        .as_vec()
        .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some("sysmon")));
    if sysmon_tag {
        return None;
    }
    if let Some(ch) = contains_builtin_channel(&doc["detection"]) {
        let uuid = doc["id"].as_str().unwrap_or("");
        let title = doc["title"].as_str().unwrap_or("");
        let level = doc["level"].as_str().unwrap_or("");
        let description = doc["description"].as_str().unwrap_or("");
        let category = doc["logsource"]["category"].as_str().unwrap_or("");
        let services = doc["logsource"]["service"].as_str().unwrap_or("");
        let mut tags: Vec<String> = doc["tags"].as_vec().map_or(vec![], |t| {
            t.iter()
                .filter_map(|tag| tag.as_str().map(normalize_tag))
                .collect()
        });
        for tag in &tags {
            if suspicious_attack_tag(tag) {
                eprintln!("[WARN] {uuid} ({title}): unrecognized ATT&CK tag '{tag}'");
            }
        }
        let mut parent_techniques = HashSet::new();
        for tag in &tags {
            if tag.starts_with("T")
                && tag.contains('.')
                && let Some(parent) = tag.split('.').next()
            {
                parent_techniques.insert(parent.to_string());
            }
        }
        // Sort before appending: HashSet iteration order is randomized per process, which
        // would otherwise reorder these tags on every run and make the generated JSON
        // differ even when no rule changed.
        let mut parent_techniques: Vec<String> = parent_techniques.into_iter().collect();
        parent_techniques.sort();
        for parent in parent_techniques {
            if !tags.contains(&parent) {
                tags.push(parent);
            }
        }

        let mut event_ids = HashSet::new();
        let mut subcategories = HashSet::new();
        extract_event_ids(&doc, &mut event_ids);
        for event_id in &event_ids {
            for (eid, subcategory) in eid_subcategory_pair {
                if eid == event_id {
                    subcategories.insert(subcategory.clone());
                }
            }
        }
        let mut event_ids: Vec<String> = event_ids.into_iter().collect();
        event_ids.sort();
        let mut subcategories: Vec<String> = subcategories.into_iter().collect();
        subcategories.sort();
        return Some(json!({
            "id": uuid,
            "title": title,
            "channel": ch.iter().map(|c| c.to_string()).collect::<Vec<String>>(),
            "level": level,
            "event_ids": event_ids,
            "subcategory_guids": subcategories,
            "description": description,
            "service": services,
            "category": category,
            "tags": tags
        }));
    }
    None
}

fn load_event_id_guid_pairs(file_path: &str) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let mut rdr = ReaderBuilder::new()
        .has_headers(true)
        .from_path(file_path)?;

    let mut pairs = Vec::new();
    for result in rdr.records() {
        let record = result?;
        let event_id = record.get(0).unwrap_or("").to_string();
        let guid = record.get(3).unwrap_or("").to_string();
        if !event_id.is_empty() && !guid.is_empty() {
            pairs.push((event_id, guid));
        }
    }
    Ok(pairs)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <file_path> <dir>", args[0]);
        std::process::exit(1);
    }

    let dir = &args[1];
    let yml_files = list_yml_files(dir);
    let mut results = Vec::new();

    let file_path = &args[2];
    let eid_subcategory_pair = load_event_id_guid_pairs(file_path)?;

    let out = &args[3];

    for file in yml_files {
        let contents = fs::read_to_string(&file).expect("Unable to read file");
        let docs = YamlLoader::load_from_str(&contents).expect("Unable to parse YAML");
        for doc in docs {
            if let Some(res) = parse_yaml(doc, &eid_subcategory_pair) {
                results.push(res);
            }
        }
    }

    let json_output = serde_json::to_string_pretty(&results)?;
    println!("{}", json_output);
    write(out, json_output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_v19_tactics() {
        // v19 renamed Defense Evasion to Stealth (same ID) and added Defense Impairment.
        assert_eq!(normalize_tag("attack.stealth"), "TA0005");
        assert_eq!(normalize_tag("attack.defense-evasion"), "TA0005");
        assert_eq!(normalize_tag("attack.defense-impairment"), "TA0112");
    }

    #[test]
    fn maps_pre_v19_tactics() {
        assert_eq!(normalize_tag("attack.reconnaissance"), "TA0043");
        assert_eq!(normalize_tag("attack.execution"), "TA0002");
        assert_eq!(normalize_tag("attack.exfiltration"), "TA0010");
        assert_eq!(normalize_tag("attack.command-and-control"), "TA0011");
        assert_eq!(normalize_tag("attack.impact"), "TA0040");
    }

    #[test]
    fn maps_techniques() {
        assert_eq!(normalize_tag("attack.t1136"), "T1136");
        assert_eq!(normalize_tag("attack.t1136.001"), "T1136.001");
    }

    #[test]
    fn passes_other_tags_through() {
        for tag in [
            "attack.s0183",
            "attack.g0010",
            "attack.ds0005",
            "cve.2025-53770",
            "car.2013-05-002",
            "detection.emerging-threats",
        ] {
            assert_eq!(normalize_tag(tag), tag);
        }
    }

    #[test]
    fn flags_malformed_attack_tags() {
        // Real typos in hayabusa-rules: the technique ID is lost entirely.
        assert!(suspicious_attack_tag("attack.1136.001"));
        assert!(suspicious_attack_tag("attack.11136.001"));
        // A tactic name we do not know yet should surface rather than be emitted raw.
        assert!(suspicious_attack_tag("attack.some-new-tactic"));
    }

    #[test]
    fn does_not_flag_valid_tags() {
        for tag in [
            "attack.s0183",
            "attack.g0010",
            "attack.c0028",
            "attack.ds0005",
            "attack.m1042",
            "T1136.001",
            "TA0005",
            "cve.2025-53770",
        ] {
            assert!(!suspicious_attack_tag(tag), "{tag} should not be flagged");
        }
    }
}
