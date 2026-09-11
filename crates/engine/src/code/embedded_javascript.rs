/// Extract executable JavaScript from EJS `<script>` elements while preserving
/// every byte offset and line number. Markup, tutorial snippets, and EJS
/// directives become whitespace, so they cannot act as executable AST evidence.
pub(crate) fn extract_ejs_scripts(source: &str) -> Option<String> {
    let lower = source.to_ascii_lowercase();
    let bytes = source.as_bytes();
    let mut extracted = bytes
        .iter()
        .map(|byte| {
            if matches!(byte, b'\r' | b'\n') {
                *byte
            } else {
                b' '
            }
        })
        .collect::<Vec<_>>();
    let mut cursor = 0;
    let mut copied = false;

    while let Some(relative_start) = lower[cursor..].find("<script") {
        let start = cursor + relative_start;
        let Some(open_end_relative) = lower[start..].find('>') else {
            break;
        };
        let open_end = start + open_end_relative;
        let Some(close_relative) = lower[open_end + 1..].find("</script>") else {
            break;
        };
        let close = open_end + 1 + close_relative;
        let opening = &lower[start..=open_end];
        let executable_type = !opening.contains("type=")
            || opening.contains("javascript")
            || opening.contains("type=\"module\"")
            || opening.contains("type='module'");
        if executable_type
            && source[open_end + 1..close]
                .chars()
                .any(|ch| !ch.is_whitespace())
        {
            extracted[open_end + 1..close].copy_from_slice(&bytes[open_end + 1..close]);
            copied = true;
        }
        cursor = close + "</script>".len();
    }

    if !copied {
        return None;
    }
    mask_ejs_directives(&mut extracted);
    String::from_utf8(extracted).ok()
}

fn mask_ejs_directives(source: &mut [u8]) {
    let mut cursor = 0;
    while cursor + 1 < source.len() {
        let Some(start_relative) = source[cursor..].windows(2).position(|pair| pair == b"<%")
        else {
            break;
        };
        let start = cursor + start_relative;
        let Some(end_relative) = source[start + 2..]
            .windows(2)
            .position(|pair| pair == b"%>")
        else {
            break;
        };
        let end = start + 2 + end_relative + 2;
        let directive = String::from_utf8_lossy(&source[start..end]);
        let normalized = directive
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect::<String>()
            .to_ascii_lowercase();
        for byte in &mut source[start..end] {
            if !matches!(*byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
        if normalized.contains("apitoken") && end - start == "MEHSCAN_TOKEN".len() {
            source[start..end].copy_from_slice(b"MEHSCAN_TOKEN");
        } else if end - start >= 4 {
            source[start..start + 4].copy_from_slice(b"null");
        }
        cursor = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_script_bodies_and_preserves_offsets() {
        let source = "<pre>event.data</pre>\n<script>\nconst token=\"<%-apiToken%>\";\ndocument.body.innerHTML=event.data;\n</script>";
        let extracted = extract_ejs_scripts(source).expect("script");
        assert_eq!(extracted.len(), source.len());
        assert!(!extracted.contains("<pre>"));
        assert!(extracted.contains("MEHSCAN_TOKEN"));
        assert!(extracted.contains("document.body.innerHTML"));
        assert_eq!(
            extracted.find("document.body.innerHTML"),
            source.find("document.body.innerHTML")
        );
    }
}
