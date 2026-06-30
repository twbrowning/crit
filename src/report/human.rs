//! Human-readable, optionally colorized terminal output.

use crate::finding::{Finding, Severity};
use owo_colors::{OwoColorize, Stream};

fn severity_styled(sev: Severity) -> String {
    let label = sev.as_str().to_uppercase();
    match sev {
        Severity::Error => label
            .if_supports_color(Stream::Stdout, |t| t.red().bold().to_string())
            .to_string(),
        Severity::Warning => label
            .if_supports_color(Stream::Stdout, |t| t.yellow().bold().to_string())
            .to_string(),
        Severity::Info => label
            .if_supports_color(Stream::Stdout, |t| t.blue().to_string())
            .to_string(),
        Severity::Note => label
            .if_supports_color(Stream::Stdout, |t| t.cyan().to_string())
            .to_string(),
    }
}

/// Render all findings plus a summary. `files_scanned`/`files_skipped` feed the
/// trailing summary line.
pub fn render_human(findings: &[Finding], files_scanned: usize, files_skipped: usize) -> String {
    let mut out = String::new();

    for f in findings {
        let loc = format!("{}:{}:{}", f.file.display(), f.start.line, f.start.column);
        out.push_str(&format!(
            "{} {} [{}]\n",
            severity_styled(f.severity),
            loc.if_supports_color(Stream::Stdout, |t| t.bold().to_string()),
            f.rule_id
                .if_supports_color(Stream::Stdout, |t| t.dimmed().to_string()),
        ));
        out.push_str(&format!("  {}\n", f.message));

        // Source line with a caret underline spanning the match on its first line.
        let line_no = f.start.line;
        let gutter = format!("{line_no:>5} | ");
        out.push_str(&format!(
            "{}{}\n",
            gutter.if_supports_color(Stream::Stdout, |t| t.dimmed().to_string()),
            f.snippet
        ));
        let underline_len = if f.end.line == f.start.line {
            f.end.column.saturating_sub(f.start.column).max(1)
        } else {
            f.snippet.chars().count().saturating_sub(f.start.column - 1).max(1)
        };
        let pad = " ".repeat(gutter.len() + f.start.column.saturating_sub(1));
        let carets = "^".repeat(underline_len);
        out.push_str(&format!(
            "{}{}\n\n",
            pad,
            carets.if_supports_color(Stream::Stdout, |t| match f.severity {
                Severity::Error => t.red().to_string(),
                Severity::Warning => t.yellow().to_string(),
                _ => t.blue().to_string(),
            })
        ));
    }

    let (errors, warnings, others) = tally(findings);
    if findings.is_empty() {
        out.push_str(&format!(
            "No findings. Scanned {files_scanned} file(s), skipped {files_skipped}.\n"
        ));
    } else {
        out.push_str(&format!(
            "{} finding(s): {} error, {} warning, {} info/note  \
             (scanned {files_scanned} file(s), skipped {files_skipped})\n",
            findings.len(),
            errors,
            warnings,
            others
        ));
    }
    out
}

fn tally(findings: &[Finding]) -> (usize, usize, usize) {
    let mut e = 0;
    let mut w = 0;
    let mut o = 0;
    for f in findings {
        match f.severity {
            Severity::Error => e += 1,
            Severity::Warning => w += 1,
            _ => o += 1,
        }
    }
    (e, w, o)
}
