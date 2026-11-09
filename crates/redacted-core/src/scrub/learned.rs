//! Learned tier: secrets `init` stored as a sha256 and length, matched exactly
//! or by their derived shape, and the markers that replace them.

use sha2::{Digest, Sha256};

use super::{ScrubResult, Scrubber, last_chars};
use crate::config::LearnedSecret;

impl Scrubber {
    /// Shapes first, then exact hashes on the rewritten text, so a span a shape
    /// already redacted is a marker and cannot match again.
    pub(super) fn scrub_learned(&self, result: &mut ScrubResult) {
        for (name, shape) in &self.learned_shapes {
            let spans = shape
                .find_iter(&result.text)
                .map(|found| (found.start(), found.end(), name.as_str()))
                .collect();
            redact_spans(result, spans);
        }
        if self.learned_name_by_hash.is_empty() {
            return;
        }
        // A value holding `@`, `(` or quotes spans several value-char runs, so
        // non-whitespace runs go second, on the rewritten text so a marker is never matched again.
        for run_regex in [&self.value_char_run, &self.non_whitespace_run] {
            let runs = run_regex
                .find_iter(&result.text)
                .map(|found| (found.start(), found.end()))
                .collect();
            let spans = self.spans_matching_learned_hashes(&result.text, runs);
            redact_spans(result, spans);
        }
    }

    fn spans_matching_learned_hashes(
        &self,
        text: &str,
        runs: Vec<(usize, usize)>,
    ) -> Vec<(usize, usize, &str)> {
        let mut spans = Vec::new();
        // The `'runs` label names this outer loop so an inner loop can continue it.
        'runs: for (run_start, run_end) in runs {
            // `KEY=value` is one run, so also try each suffix after `=` or `:`.
            let mut starts = vec![run_start];
            let run = &text[run_start..run_end];
            starts.extend(
                run.match_indices(['=', ':'])
                    .map(|(i, _)| run_start + i + 1),
            );
            for start in starts {
                for (candidate_start, candidate_end) in peeled_candidate_spans(text, start, run_end)
                {
                    if candidate_start >= candidate_end
                        || !self
                            .learned_byte_lengths
                            .contains(&(candidate_end - candidate_start))
                    {
                        continue;
                    }
                    let hash = sha256_hex(&text[candidate_start..candidate_end]);
                    if let Some(name) = self.learned_name_by_hash.get(&hash) {
                        spans.push((candidate_start, candidate_end, name.as_str()));
                        // One learned match per run, then on to the next run.
                        continue 'runs;
                    }
                }
            }
        }
        spans
    }
}

/// Punctuation and quotes around a value stay inside its run, so try each stage of
/// peeling them: trailing `.:!?,;)}]`, then one matching quote pair, then trailing again.
/// Every stage is a candidate, so a quoted value ending in `)` still matches.
fn peeled_candidate_spans(text: &str, start: usize, end: usize) -> [(usize, usize); 4] {
    const TRAILING_PUNCTUATION: [char; 9] = ['.', ':', '!', '?', ',', ';', ')', '}', ']'];
    let trimmed_end = start
        + text[start..end]
            .trim_end_matches(TRAILING_PUNCTUATION)
            .len();
    // Slice pattern: the first and last byte are the same quote character.
    let (inner_start, inner_end) = match text.as_bytes()[start..trimmed_end] {
        [quote @ (b'"' | b'\''), .., last] if quote == last => (start + 1, trimmed_end - 1),
        _ => (start, trimmed_end),
    };
    let inner_trimmed_end = inner_start
        + text[inner_start..inner_end]
            .trim_end_matches(TRAILING_PUNCTUATION)
            .len();
    [
        (start, end),
        (start, trimmed_end),
        (inner_start, inner_end),
        (inner_start, inner_trimmed_end),
    ]
}

pub fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The 4-char hint, or None when it would be a third or more of the value.
pub fn learned_value_hint(value: &str) -> Option<&str> {
    if value.chars().count() < 12 {
        return None;
    }
    Some(last_chars(value, 4))
}

/// Turns a name and its secret value into a `LearnedSecret`: the value's sha256,
/// its byte length and, for values with a literal prefix, a shape regex that also
/// catches rotated keys. The raw value is never stored. Rejects values with
/// whitespace or under eight characters.
pub fn learn(key: &str, value: &str) -> Result<LearnedSecret, &'static str> {
    if value.contains(char::is_whitespace) {
        return Err("cannot match (contains spaces)");
    }
    if value.chars().count() < 8 {
        return Err("too short");
    }
    Ok(LearnedSecret {
        name: key.to_lowercase(),
        sha256: sha256_hex(value),
        byte_len: value.len(),
        shape: derive_shape(value),
    })
}

/// A regex for the value's shape: its literal prefix (ending at the last `_`/`-`
/// in the first 13 chars) plus the character classes and a length window around
/// the tail, so a rotated key of the same shape still matches. None when there is
/// no short separated prefix or the tail holds non-token characters.
pub fn derive_shape(sample: &str) -> Option<String> {
    // Byte index of the 13th char, so the slice never splits a multi-byte char.
    let head_end = sample
        .char_indices()
        .nth(12)
        .map_or(sample.len(), |(i, _)| i);
    let prefix_end = sample[..head_end].rfind(['_', '-'])? + 1;
    let (prefix, rest) = sample.split_at(prefix_end);
    if prefix.chars().count() < 3 || rest.is_empty() {
        return None;
    }
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    let charset: String = [
        (rest.chars().any(|c| c.is_ascii_lowercase()), "a-z"),
        (rest.chars().any(|c| c.is_ascii_uppercase()), "A-Z"),
        (rest.chars().any(|c| c.is_ascii_digit()), "0-9"),
        (rest.contains('_'), "_"),
        (rest.contains('-'), "-"),
    ]
    .iter()
    .filter(|(present, _)| *present)
    .map(|(_, class)| *class)
    .collect();
    let rest_len = rest.chars().count();
    Some(format!(
        r"\b{}[{charset}]{{{},{}}}\b",
        regex::escape(prefix),
        rest_len.saturating_sub(4).max(1),
        rest_len + 4
    ))
}

/// Rewrites sorted, non-overlapping spans as learned markers.
fn redact_spans(result: &mut ScrubResult, spans: Vec<(usize, usize, &str)>) {
    if spans.is_empty() {
        return;
    }
    let text = &result.text;
    let mut out = String::with_capacity(text.len());
    let mut copied_until = 0;
    for &(start, end, name) in &spans {
        out.push_str(&text[copied_until..start]);
        match learned_value_hint(&text[start..end]) {
            Some(hint) => out.push_str(&format!("[REDACTED:{name} ...{hint}]")),
            None => out.push_str(&format!("[REDACTED:{name}]")),
        }
        copied_until = end;
    }
    out.push_str(&text[copied_until..]);
    result.text = out;
    for (_, _, name) in spans {
        result.add_redactions(name, 1);
    }
}

#[cfg(test)]
mod tests;
