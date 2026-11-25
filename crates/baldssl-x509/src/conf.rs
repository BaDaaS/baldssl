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

use std::str::FromStr;

use baldssl_core::{Error, Result};

use crate::extension::{Extension, Extensions};

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

/// One `name = value` line of a section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfValue {
    /// The name, before the `=`, trimmed.
    pub name: String,
    /// The value, after it, trimmed.
    pub value: String,
}

/// A section: its name and its values, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Section {
    name: String,
    values: Vec<ConfValue>,
}

impl Section {
    /// A section without values.
    fn new(name: &str) -> Self {
        Section {
            name: name.to_string(),
            values: Vec::new(),
        }
    }
}

/// A configuration file, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    sections: Vec<Section>,
}

/// Reads a configuration file.
///
/// # Errors
///
/// [`Error::Usage`] for a line with no `=` or a malformed header, as
/// OpenSSL's "missing equal sign"; [`Error::Unsupported`] for the syntax
/// baldssl does not read (see the module).
impl FromStr for Config {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        // The section the lines go to, and the others, read so far.
        let mut current = Section::new(DEFAULT_SECTION);
        let mut others: Vec<Section> = Vec::new();
        for (number, raw) in text.lines().enumerate() {
            let line_number = number.saturating_add(1);
            let line = raw.split_once('#').map_or(raw, |(l, _)| l).trim();
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
                let next = match others.iter().position(|s| s.name == name) {
                    Some(i) => others.remove(i),
                    None => Section::new(name),
                };
                others.push(core::mem::replace(&mut current, next));
                continue;
            }
            let (name, value) = line.split_once('=').ok_or_else(|| {
                Error::Usage(format!(
                    "configuration line {line_number}: missing equal sign"
                ))
            })?;
            replace_push(
                &mut current.values,
                ConfValue {
                    name: name.trim().to_string(),
                    value: value.trim().to_string(),
                },
                |a, b| a.name == b.name,
            );
        }
        others.push(current);
        Ok(Config { sections: others })
    }
}

/// The section of the lines before the first header (`conf_def.c`).
const DEFAULT_SECTION: &str = "default";

impl Config {
    /// The extensions of a section, in order, a later one replacing an
    /// earlier one of its kind, as OpenSSL adds a section; a value
    /// `@other` reads the section `other` of this configuration.
    ///
    /// # Errors
    ///
    /// As the `FromStr` of [`Extension`] for each line; [`Error::Usage`]
    /// when there is no such section.
    pub fn extensions(&self, section: &str) -> Result<Extensions> {
        self.section_opt(section)
            .ok_or_else(|| {
                Error::Usage(format!("no extension section {section:?}"))
            })?
            .iter()
            .map(|v| Extension::from_name_value(&v.name, &v.value, Some(self)))
            .collect()
    }

    /// The values of a section, in order; `None` when there is no such
    /// section.
    #[must_use]
    pub fn section_opt(&self, name: &str) -> Option<&[ConfValue]> {
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
            .find(|v| v.name == name)
            .map(|v| v.value.as_str())
    }
}

#[cfg(test)]
mod tests;
