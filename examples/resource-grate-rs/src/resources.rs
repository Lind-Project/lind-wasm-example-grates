use std::collections::{HashMap, HashSet};

/// Renewable resources: rate-limited via token bucket (rate per second).
pub const RENEWABLE_RESOURCES: &[&str] = &[
    "cpu", "filewrite", "fileread", "netsend", "netrecv",
    "loopsend", "looprecv", "lograte", "random",
];

/// Fungible item resources: hard cap on concurrent count.
pub const FUNGIBLE_RESOURCES: &[&str] = &[
    "events", "filesopened", "insockets", "outsockets",
];

/// Individual item resources: port allowlists.
pub const INDIVIDUAL_RESOURCES: &[&str] = &["messport", "connport"];

/// Parsed resource configuration from a repy-style resource file.
pub struct ResourceConfig {
    pub renewable: HashMap<String, f64>,
    pub fungible: HashMap<String, usize>,
    pub individual: HashMap<String, HashSet<u16>>,
    pub hard_caps: HashMap<String, u64>,
}

impl ResourceConfig {
    pub fn parse_file(path: &str) -> Self {
        let content = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read resource file '{}': {}", path, e));
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Self {
        let mut renewable = HashMap::new();
        let mut fungible = HashMap::new();
        let mut individual: HashMap<String, HashSet<u16>> = HashMap::new();
        let mut hard_caps = HashMap::new();

        for line in content.lines() {
            // Strip comments.
            let line = match line.find('#') {
                Some(pos) => &line[..pos],
                None => line,
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() != 3 || tokens[0] != "resource" {
                continue;
            }

            let name = tokens[1];
            let value_str = tokens[2];

            if RENEWABLE_RESOURCES.contains(&name) {
                let value: f64 = value_str
                    .parse()
                    .unwrap_or_else(|_| panic!("Invalid value for {}: {}", name, value_str));
                renewable.insert(name.to_string(), value);
            } else if FUNGIBLE_RESOURCES.contains(&name) {
                let value: usize = value_str
                    .parse()
                    .unwrap_or_else(|_| panic!("Invalid value for {}: {}", name, value_str));
                fungible.insert(name.to_string(), value);
            } else if INDIVIDUAL_RESOURCES.contains(&name) {
                let value: u16 = value_str
                    .parse()
                    .unwrap_or_else(|_| panic!("Invalid value for {}: {}", name, value_str));
                individual.entry(name.to_string()).or_default().insert(value);
            } else if name == "memory" || name == "diskused" {
                let value: u64 = value_str
                    .parse()
                    .unwrap_or_else(|_| panic!("Invalid value for {}: {}", name, value_str));
                hard_caps.insert(name.to_string(), value);
            }
        }

        ResourceConfig {
            renewable,
            fungible,
            individual,
            hard_caps,
        }
    }
}
