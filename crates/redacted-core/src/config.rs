//! Config data types shared by the engine: app policy (`Config`) and engine
//! overrides (`EngineConfig`). Reading and merging these from disk lives in the
//! CLI crate; this module is pure data so it compiles to WASM.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    #[serde(rename = "override")]
    pub project_override: bool,
    #[serde(rename = "whitelist")]
    pub disabled_patterns: Vec<String>,
    #[serde(rename = "allow")]
    pub allowed_keys: Vec<String>,
    pub ignore_internal_tools: bool,
    pub version: u32,
    pub learned: Vec<LearnedSecret>,
    pub heuristic: HeuristicConfig,
    pub pii: PiiConfig,
}

/// A secret learned by `init`: its hash and byte length, never the value.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LearnedSecret {
    pub name: String,
    pub sha256: String,
    #[serde(rename = "len")]
    pub byte_len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
}

// Default heuristic thresholds. The includes_key guards in scrub/guards.rs use
// DEFAULT_MIN_CHAR_CLASSES and DEFAULT_MIN_ENTROPY as fixed values on purpose,
// whatever the config says, to tell a random segment from an identifier.
pub const DEFAULT_MIN_LENGTH: usize = 16;
pub const DEFAULT_MAX_LENGTH: usize = 128;
pub const DEFAULT_MIN_CHAR_CLASSES: usize = 3;
pub const DEFAULT_MIN_ENTROPY: f64 = 3.5;

/// Opt-in entropy tier. Each absent threshold takes its default; an explicit
/// value, zero included, is used as written.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HeuristicConfig {
    pub enabled: bool,
    // serde calls the named function when the key is missing.
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    #[serde(default = "default_max_length")]
    pub max_length: usize,
    #[serde(default = "default_min_char_classes")]
    pub min_char_classes: usize,
    #[serde(default = "default_min_entropy")]
    pub min_entropy: f64,
}

// Written by hand, not derived: a derived Default would give zero thresholds.
impl Default for HeuristicConfig {
    fn default() -> Self {
        HeuristicConfig {
            enabled: false,
            min_length: DEFAULT_MIN_LENGTH,
            max_length: DEFAULT_MAX_LENGTH,
            min_char_classes: DEFAULT_MIN_CHAR_CLASSES,
            min_entropy: DEFAULT_MIN_ENTROPY,
        }
    }
}

fn default_min_length() -> usize {
    DEFAULT_MIN_LENGTH
}

fn default_max_length() -> usize {
    DEFAULT_MAX_LENGTH
}

fn default_min_char_classes() -> usize {
    DEFAULT_MIN_CHAR_CLASSES
}

fn default_min_entropy() -> f64 {
    DEFAULT_MIN_ENTROPY
}

/// Opt-in PII tier: each toggle turns on the engine.yml row of the same name.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct PiiConfig {
    pub email: bool,
    pub phone: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct CustomPattern {
    pub name: String,
    pub regex: String,
}

/// An engine.yml from 0.7 still loads: serde skips its retired `keywords`,
/// `heuristic` and `value_safe_char` keys like any other unknown key.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    #[serde(rename = "override")]
    pub project_override: bool,
    pub allow_values: Vec<String>,
    pub patterns: Vec<CustomPattern>,
}

/// A config file that exists but does not read or parse. Path and message stay
/// apart because the message can quote the file, which hook mode keeps from the model.
#[derive(Debug)]
pub struct ConfigError {
    pub path: PathBuf,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}: {}", self.path.display(), self.message)
    }
}

/// Lets `?` hand a ConfigError to the commands, which all fail with a String.
impl From<ConfigError> for String {
    fn from(error: ConfigError) -> String {
        error.to_string()
    }
}

pub const VENDOR_ONLY_NOTICE: &str = "vendor signatures only, no learned secrets, heuristic off; run `redacted init --env PATH` to learn yours";

/// Only the vendor tier is active: nothing catches a secret without a known prefix.
pub fn is_vendor_only(config: &Config) -> bool {
    config.learned.is_empty() && !config.heuristic.enabled
}
