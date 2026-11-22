//! OpenSSL configuration files, as far as extension files use them
//! (`x509 -extfile`): `[ section ]` headers, `name = value` lines and `#`
//! comments, as OpenSSL's `NCONF` reads them (`crypto/conf/conf_def.c`).
//! Lines before the first header belong to the section `default`.
//!
//! A name given twice in a section keeps the later value, which moves to
//! the end: OpenSSL's `_CONF_add_string` pushes the new value and deletes
//! the old one, the same "replace" rule as for extensions
//! ([`replace_push`]).
//!
//! Not read, and reported as unsupported rather than misread: quotes,
//! backslash escapes and line continuations, `$` variable expansion, and
//! `.include` and other directives.

use baldssl_core::{Error, Result};

/// Appends `item`, after removing the items `same` says it replaces: the
/// "replace" mode of OpenSSL, for configuration values and for extensions.
/// Folding it over a list keeps, of each class, the last item, in the
/// order of the last items.
pub(crate) fn replace_push<T, F>(items: &mut Vec<T>, item: T, same: F)
where
    F: Fn(&T, &T) -> bool,
{
    items.retain(|old| !same(old, &item));
    items.push(item);
}

/// A section: its name and its values, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Section {
    name: String,
    values: Vec<(String, String)>,
}

/// A configuration file, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    sections: Vec<Section>,
}

impl Config {
    /// Reads a configuration file.
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] for a line with no `=` or a malformed header, as
    /// OpenSSL's "missing equal sign"; [`Error::Unsupported`] for the
    /// syntax baldssl does not read (see the module).
    pub fn parse(text: &str) -> Result<Self> {
        let mut config = Config {
            sections: vec![Section {
                name: "default".into(),
                values: Vec::new(),
            }],
        };
        let mut current = 0;
        for (number, raw) in text.lines().enumerate() {
            let line_number = number.saturating_add(1);
            let line = raw.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            if line.contains(['"', '\'', '\\', '$']) || line.starts_with('.') {
                return Err(Error::unsupported(format!(
                    "configuration line {line_number}: quotes, escapes, \
                     variables and directives"
                )));
            }
            if let Some(header) = line.strip_prefix('[') {
                let name = header
                    .strip_suffix(']')
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                    .ok_or_else(|| {
                        Error::Usage(format!(
                            "configuration line {line_number}: bad section \
                             header"
                        ))
                    })?;
                // A section opened twice gathers both parts, as in OpenSSL.
                current = config
                    .sections
                    .iter()
                    .position(|s| s.name == name)
                    .unwrap_or_else(|| {
                        config.sections.push(Section {
                            name: name.to_string(),
                            values: Vec::new(),
                        });
                        config.sections.len().saturating_sub(1)
                    });
                continue;
            }
            let (name, value) = line.split_once('=').ok_or_else(|| {
                Error::Usage(format!(
                    "configuration line {line_number}: missing equal sign"
                ))
            })?;
            if let Some(section) = config.sections.get_mut(current) {
                replace_push(
                    &mut section.values,
                    (name.trim().to_string(), value.trim().to_string()),
                    |a, b| a.0 == b.0,
                );
            }
        }
        Ok(config)
    }

    /// The values of a section, in order; `None` when there is no such
    /// section.
    #[must_use]
    pub fn section_opt(&self, name: &str) -> Option<&[(String, String)]> {
        self.sections
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.values.as_slice())
    }

    /// One value of a section.
    #[must_use]
    pub fn value_opt(&self, section: &str, name: &str) -> Option<&str> {
        self.section_opt(section)?
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(test)]
mod tests;
