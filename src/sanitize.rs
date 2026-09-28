//! HTML sanitization utilities

/// Escape HTML special characters (prevents XSS)
#[must_use]
pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Sanitize HTML by removing dangerous tags and attributes
/// This is a basic implementation - for production use consider
/// a dedicated library like ammonia
///
/// The passes below reuse two alternating buffers instead of allocating
/// a fresh `String` per pass. Matching logic is unchanged; only the
/// allocation pattern differs, so sanitization behavior is preserved.
#[must_use]
pub fn sanitize_html(s: &str) -> String {
    // Tag patterns are built once; the previous form rebuilt them on
    // every pass through `format!` inside `remove_tag`.
    const TAGS: [&str; 6] = ["script", "style", "iframe", "object", "embed", "form"];

    let mut current = s.to_string();
    let mut next = String::with_capacity(s.len());

    for tag in TAGS {
        next.clear();
        remove_tag_into(&current, tag, &mut next);
        std::mem::swap(&mut current, &mut next);
    }

    next.clear();
    remove_event_handlers_into(&current, &mut next);
    std::mem::swap(&mut current, &mut next);

    // Two scheme strips ping-pong across the same buffers; no wrapper
    // allocation remains between them.
    next.clear();
    replace_ascii_case_insensitive_into(&current, "javascript:", "", &mut next);
    std::mem::swap(&mut current, &mut next);

    next.clear();
    replace_ascii_case_insensitive_into(&current, "vbscript:", "", &mut next);
    std::mem::swap(&mut current, &mut next);

    current
}

fn remove_tag_into(s: &str, tag: &str, out: &mut String) {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    remove_tag_between(s, &open, &close, out);
}

fn remove_tag_between(s: &str, open: &str, close: &str, result: &mut String) {

    let mut cursor = 0usize;
    while let Some(start) = find_ascii_case_insensitive(s, &open, cursor) {
        result.push_str(&s[cursor..start]);

        if let Some(end) = find_ascii_case_insensitive(s, &close, start) {
            cursor = end + close.len();
        } else if let Some(gt) = s[start..].find('>') {
            cursor = start + gt + 1;
        } else {
            cursor = s.len();
        }
    }
    result.push_str(&s[cursor..]);
}

/// Same matching loop as `remove_event_handlers`, writing into a reused
/// buffer instead of cloning the input first.
fn remove_event_handlers_into(s: &str, result: &mut String) {
    let event_handlers = [
        "onclick", "onload", "onerror", "onmouseover", "onmouseout",
        "onfocus", "onblur", "onsubmit", "onchange", "onkeyup",
        "onkeydown", "onkeypress",
    ];

    // Seed the working buffer with the input; the loop below is
    // unchanged from the previous clone-then-edit form.
    result.clear();
    result.push_str(s);
    for handler in event_handlers {
        while let Some(start) = find_ascii_case_insensitive(&result, handler, 0) {
            let Some(eq_pos) = result[start..].find('=') else {
                break;
            };
            let quote_start = start + eq_pos + 1;
            let quote = result.as_bytes().get(quote_start).copied();
            let Some(quote) = quote else { break };
            if quote != b'"' && quote != b'\'' {
                break;
            }
            let next = result[quote_start + 1..]
                .find(quote as char)
                .map(|idx| quote_start + 2 + idx);
            let Some(end) = next else { break };

            result.replace_range(start..end, "");
        }
    }
}

fn replace_ascii_case_insensitive_into(
    input: &str,
    needle: &str,
    replacement: &str,
    out: &mut String,
) {
    // Reuse the buffer's existing capacity; output never exceeds input
    // length here since both replacements are deletions.
    out.clear();
    if out.capacity() < input.len() {
        out.reserve(input.len() - out.capacity());
    }
    let mut cursor = 0usize;
    while let Some(idx) = find_ascii_case_insensitive(input, needle, cursor) {
        out.push_str(&input[cursor..idx]);
        out.push_str(replacement);
        cursor = idx + needle.len();
    }
    out.push_str(&input[cursor..]);
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str, from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() {
        return None;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.len() > h.len().saturating_sub(from) {
        return None;
    }

    for i in from..=h.len() - n.len() {
        if h[i..i + n.len()]
            .iter()
            .zip(n.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return Some(i);
        }
    }
    None
}

/// Strip all HTML tags
#[must_use]
pub fn strip_tags(s: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(c),
            _ => {}
        }
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("\"hello\""), "&quot;hello&quot;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
    }

    #[test]
    fn test_strip_tags() {
        assert_eq!(strip_tags("<p>Hello</p>"), "Hello");
        assert_eq!(strip_tags("<b>Bold</b> text"), "Bold text");
    }

    #[test]
    fn test_sanitize_html() {
        let input = "<p>Hello</p><script>alert('xss')</script>";
        let sanitized = sanitize_html(input);
        assert!(!sanitized.contains("script"));
    }

    #[test]
    fn sanitize_handles_unicode_without_corruption() {
        let input = "Привет<script>alert(1)</script>世界";
        let sanitized = sanitize_html(input);
        assert_eq!(sanitized, "Привет世界");
    }

    #[test]
    fn sanitize_removes_case_insensitive_js_scheme() {
        let input = r#"<a href="JaVaScRiPt:alert(1)">x</a>"#;
        let sanitized = sanitize_html(input);
        assert!(!sanitized.to_lowercase().contains("javascript:"));
    }
}
