//! Checks that every interface text has a translation in each catalog.

use std::collections::{HashMap, HashSet};

/// One `@tr(...)` call of a Slint file: the Slint context (the component
/// name, or the text set with `"context" =>`), the text and its plural form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TrCall {
    context: String,
    msgid: String,
    plural: Option<String>,
}

/// Read a string literal that starts at `chars[*i]` (a `"`). Moves `*i`
/// after the closing quote and resolves the escapes that a `.po` file also
/// uses.
fn read_string(chars: &[char], i: &mut usize) -> String {
    let mut out = String::new();
    *i += 1;
    while *i < chars.len() && chars[*i] != '"' {
        if chars[*i] == '\\' && *i + 1 < chars.len() {
            *i += 1;
            out.push(match chars[*i] {
                'n' => '\n',
                't' => '\t',
                other => other,
            });
        } else {
            out.push(chars[*i]);
        }
        *i += 1;
    }
    *i += 1;
    out
}

fn skip_spaces(chars: &[char], i: &mut usize) {
    while *i < chars.len() && chars[*i].is_whitespace() {
        *i += 1;
    }
}

/// Find every `@tr(...)` outside comments. The context is the name of the
/// enclosing `component` or `global`, unless the call sets one.
fn slint_tr_calls(slint: &str) -> Vec<TrCall> {
    let chars: Vec<char> = slint.chars().collect();
    let mut calls = Vec::new();
    let mut component = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else if c == '"' {
            read_string(&chars, &mut i);
        } else if c == '@' && chars[i..].iter().take(4).collect::<String>() == "@tr(" {
            i += 4;
            skip_spaces(&chars, &mut i);
            if chars.get(i) != Some(&'"') {
                continue;
            }
            let first = read_string(&chars, &mut i);
            skip_spaces(&chars, &mut i);
            let arrow = chars.get(i) == Some(&'=') && chars.get(i + 1) == Some(&'>');
            let (context, msgid) = if arrow {
                i += 2;
                skip_spaces(&chars, &mut i);
                (first, read_string(&chars, &mut i))
            } else {
                (component.clone(), first)
            };
            skip_spaces(&chars, &mut i);
            let mut plural = None;
            if chars.get(i) == Some(&'|') {
                i += 1;
                skip_spaces(&chars, &mut i);
                plural = Some(read_string(&chars, &mut i));
            }
            calls.push(TrCall {
                context,
                msgid,
                plural,
            });
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '-')
            {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            if word == "component" || word == "global" {
                skip_spaces(&chars, &mut i);
                let name_start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                component = chars[name_start..i].iter().collect();
            }
        } else {
            i += 1;
        }
    }
    calls
}

/// The entries of a catalog: (context, msgid) to the plural msgid and the
/// translated forms. The header entry (empty msgid) is left out.
type PoEntries = HashMap<(String, String), (Option<String>, Vec<String>)>;

/// The value of a `keyword "text"` line, or `None` for another keyword.
fn po_value(line: &str, keyword: &str) -> Option<String> {
    let rest = line.strip_prefix(keyword)?;
    if !rest.starts_with(' ') {
        return None;
    }
    let body = rest.trim().strip_prefix('"')?.strip_suffix('"')?;
    let chars: Vec<char> = format!("\"{body}\"").chars().collect();
    let mut i = 0;
    Some(read_string(&chars, &mut i))
}

#[derive(Default)]
struct PoEntry {
    context: String,
    msgid: Option<String>,
    plural: Option<String>,
    forms: Vec<String>,
}

fn parse_po_entries(po: &str) -> PoEntries {
    let mut entries = PoEntries::new();
    let mut current = PoEntry::default();
    let mut store = |entry: PoEntry| {
        if let Some(id) = entry.msgid {
            if !id.is_empty() {
                entries.insert((entry.context, id), (entry.plural, entry.forms));
            }
        }
    };
    for line in po.lines() {
        let line = line.trim();
        if let Some(context) = po_value(line, "msgctxt") {
            store(std::mem::take(&mut current));
            current.context = context;
        } else if let Some(plural) = po_value(line, "msgid_plural") {
            current.plural = Some(plural);
        } else if let Some(id) = po_value(line, "msgid") {
            if current.msgid.is_some() {
                store(std::mem::take(&mut current));
            }
            current.msgid = Some(id);
        } else if line.starts_with("msgstr[") {
            if let Some((_, value)) = line.split_once("] ") {
                let text = po_value(&format!("msgstr {value}"), "msgstr");
                current.forms.push(text.unwrap_or_default());
            }
        } else if let Some(text) = po_value(line, "msgstr") {
            current.forms.push(text);
        } else if line.is_empty() {
            store(std::mem::take(&mut current));
        }
    }
    store(current);
    entries
}

/// Compare the texts of a Slint file with one catalog. Returns the texts
/// without a usable translation and the catalog entries that nothing uses.
fn translation_gaps(slint: &str, po: &str) -> (Vec<String>, Vec<String>) {
    let calls = slint_tr_calls(slint);
    let entries = parse_po_entries(po);
    let mut missing = Vec::new();
    for call in &calls {
        let key = (call.context.clone(), call.msgid.clone());
        let ok = match entries.get(&key) {
            None => false,
            Some((plural, forms)) => {
                !forms.is_empty()
                    && forms.iter().all(|form| !form.is_empty())
                    && match &call.plural {
                        Some(expected) => plural.as_ref() == Some(expected) && forms.len() >= 2,
                        None => true,
                    }
            }
        };
        if !ok {
            missing.push(format!("[{}] {}", call.context, call.msgid));
        }
    }
    let used: HashSet<(String, String)> = calls
        .iter()
        .map(|call| (call.context.clone(), call.msgid.clone()))
        .collect();
    let mut obsolete: Vec<String> = entries
        .keys()
        .filter(|key| !used.contains(*key))
        .map(|(context, msgid)| format!("[{context}] {msgid}"))
        .collect();
    missing.sort();
    missing.dedup();
    obsolete.sort();
    (missing, obsolete)
}

#[test]
fn translation_gaps_reports_a_missing_text() {
    let slint = "component Box { Text { text: @tr(\"Hello\"); } }";
    let po = "msgid \"\"\nmsgstr \"\"\n\nmsgctxt \"Other\"\nmsgid \"Hello\"\nmsgstr \"Ciao\"\n";
    let (missing, obsolete) = translation_gaps(slint, po);
    assert_eq!(missing, vec!["[Box] Hello".to_string()]);
    assert_eq!(obsolete, vec!["[Other] Hello".to_string()]);
}

#[test]
fn translation_gaps_reads_plural_forms_and_context() {
    let slint = "// @tr(\"Comment\")\nexport component App {\n  a: @tr(\"{n} item\" | \"{n} items\" % count);\n  b: @tr(\"Menu\" => \"Open\");\n  c: \"https://x\"; /* @tr(\"Hidden\") */\n}\n";
    let po = "msgctxt \"App\"\nmsgid \"{n} item\"\nmsgid_plural \"{n} items\"\nmsgstr[0] \"{n} voce\"\nmsgstr[1] \"{n} voci\"\n\nmsgctxt \"Menu\"\nmsgid \"Open\"\nmsgstr \"Apri\"\n";
    assert_eq!(translation_gaps(slint, po), (Vec::new(), Vec::new()));
    let empty_form = po.replace("\"{n} voci\"", "\"\"");
    let (missing, _) = translation_gaps(slint, &empty_form);
    assert_eq!(missing, vec!["[App] {n} item".to_string()]);
}

#[test]
fn translation_gaps_reports_an_obsolete_entry() {
    let slint = "component Box { x: @tr(\"One\"); }";
    let po = "msgctxt \"Box\"\nmsgid \"One\"\nmsgstr \"Uno\"\n\nmsgctxt \"Box\"\nmsgid \"Old\"\nmsgstr \"Vecchio\"\n";
    let (missing, obsolete) = translation_gaps(slint, po);
    assert!(missing.is_empty());
    assert_eq!(obsolete, vec!["[Box] Old".to_string()]);
}

/// Every text of the interface has a translation in each catalog, and no
/// catalog entry is left without a text.
#[test]
fn every_interface_text_is_translated_in_every_catalog() {
    let slint = include_str!("../ui/appwindow.slint");
    let mut problems = Vec::new();
    for (lang, catalog) in [
        ("it", include_str!("../lang/it/LC_MESSAGES/cordiale-ui.po")),
        ("fr", include_str!("../lang/fr/LC_MESSAGES/cordiale-ui.po")),
        ("de", include_str!("../lang/de/LC_MESSAGES/cordiale-ui.po")),
        ("es", include_str!("../lang/es/LC_MESSAGES/cordiale-ui.po")),
    ] {
        let (missing, obsolete) = translation_gaps(slint, catalog);
        problems.extend(missing.into_iter().map(|t| format!("{lang} missing {t}")));
        problems.extend(obsolete.into_iter().map(|t| format!("{lang} obsolete {t}")));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
