//! The CHANGELOG paragraph on the withdrawn mhfe-core 0.1.0. The harness of
//! skeptic-doc-withdrawn reads it through `#[path]`, so that both harnesses read the same
//! paragraph (CORE-10).

/// The CHANGELOG section of the release that replaced the withdrawn package.
const NOTES_VERSION: &str = "0.1.0";
/// The word of that section's paragraph about the withdrawn package.
const NOTES_WORD: &str = "withdrawn";

/// The paragraphs of the CHANGELOG section `## 0.1.0 ...` that name the withdrawn package. A
/// section runs to the next `## ` heading, a paragraph to an empty line.
pub(crate) fn withdrawn_notes(changelog: &str) -> String {
    let mut section = Vec::new();
    let mut inside = false;
    for line in changelog.lines() {
        match line.strip_prefix("## ") {
            Some(heading) => inside = heading.split_whitespace().next() == Some(NOTES_VERSION),
            None if inside => section.push(line),
            None => {}
        }
    }
    section
        .split(|line| line.is_empty())
        .map(|paragraph| paragraph.join("\n"))
        .filter(|paragraph| paragraph.contains(NOTES_WORD))
        .collect::<Vec<_>>()
        .join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_notes_are_the_paragraphs_of_the_section_that_name_the_withdrawn_package() {
        let changelog = "# Changelog\n\n## 0.2.0\n\nNot withdrawn here.\n\n\
                         ## 0.1.0 (2026-10-27)\n\nFirst.\n\nIt replaces a withdrawn 0.1.0.\n\
                         Its API differs.\n\nLast.\n";
        assert_eq!(
            withdrawn_notes(changelog),
            "It replaces a withdrawn 0.1.0.\nIts API differs."
        );
    }
}
