use percent_encoding::percent_decode_str;
use serde_json::Value;

pub const REDACTION_MASK: &str = "+++++";

const SENSITIVE_WORDS: &[&str] = &[
    "mot de passe",
    "passe",
    "code",
    "jeton",
    "token",
    "secret",
    "bearer",
    "porteur",
    "clé",
    "cle",
    "clef",
    "passwort",
    "kennwort",
    "kode",
    "träger",
    "traeger",
    "schlüssel",
    "schlussel",
    "palavra-passe",
    "palavrapasse",
    "senha",
    "código",
    "codigo",
    "portador",
    "chave",
    "contraseña",
    "contrasena",
    "clave",
    "password",
    "passwd",
    "pass",
    "key",
    "пароль",
    "код",
    "токен",
    "носитель",
    "ключ",
    "密码",
    "密碼",
    "代码",
    "代碼",
    "令牌",
    "持有者",
    "密钥",
    "密鑰",
    "钥匙",
    "鑰匙",
    "パスワード",
    "暗号",
    "コード",
    "トークン",
    "ベアラー",
    "鍵",
    "キー",
    "kata sandi",
    "katasandi",
    "sandi",
    "pembawa",
    "kunci",
];

#[must_use]
pub fn redact_uri(uri: &str) -> String {
    let Some(query_start) = uri.find('?') else {
        return uri.to_string();
    };
    let fragment_start = uri[query_start + 1..]
        .find('#')
        .map(|idx| query_start + 1 + idx);
    let query_end = fragment_start.unwrap_or(uri.len());
    let query = &uri[query_start + 1..query_end];
    let mut out = String::with_capacity(uri.len());
    out.push_str(&uri[..query_start + 1]);
    out.push_str(&redact_kv_pairs(query, &['&']));
    if let Some(fragment_start) = fragment_start {
        out.push_str(&uri[fragment_start..]);
    }
    out
}

#[must_use]
pub fn redact_payload(payload: &str) -> String {
    if looks_like_http_message(payload) {
        redact_http_message(payload)
    } else {
        redact_body(payload)
    }
}

#[must_use]
pub fn redact_http_message(message: &str) -> String {
    let (head, separator, body) = split_http_message(message);
    let redacted_head = redact_http_head(head);
    let redacted_body = multipart_boundary_from_head(head)
        .and_then(|boundary| redact_multipart_body(body, &boundary))
        .unwrap_or_else(|| redact_body(body));
    let mut out = String::with_capacity(message.len());
    out.push_str(&redacted_head);
    out.push_str(separator);
    out.push_str(&redacted_body);
    out
}

#[must_use]
pub fn is_sensitive_name(name: &str) -> bool {
    let direct = normalize_identifier(name);
    if SENSITIVE_WORDS.iter().any(|word| direct.contains(word)) {
        return true;
    }
    let decoded = percent_decode_str(name).decode_utf8_lossy();
    if decoded == name {
        return false;
    }
    let decoded = normalize_identifier(&decoded);
    SENSITIVE_WORDS.iter().any(|word| decoded.contains(word))
}

fn split_http_message(message: &str) -> (&str, &str, &str) {
    if let Some(idx) = message.find("\r\n\r\n") {
        (&message[..idx], "\r\n\r\n", &message[idx + 4..])
    } else if let Some(idx) = message.find("\n\n") {
        (&message[..idx], "\n\n", &message[idx + 2..])
    } else {
        (message, "", "")
    }
}

fn looks_like_http_message(payload: &str) -> bool {
    let first = payload.lines().next().unwrap_or_default();
    (first.starts_with("GET ")
        || first.starts_with("POST ")
        || first.starts_with("PUT ")
        || first.starts_with("PATCH ")
        || first.starts_with("DELETE ")
        || first.starts_with("HEAD ")
        || first.starts_with("OPTIONS "))
        && first.contains(" HTTP/")
}

fn redact_http_head(head: &str) -> String {
    let mut out = String::with_capacity(head.len());
    for (idx, line) in head.split('\n').enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        if idx == 0 {
            out.push_str(&redact_request_line(line));
        } else {
            out.push_str(&redact_header_line(line));
        }
        if head
            .split('\n')
            .nth(idx)
            .is_some_and(|raw| raw.ends_with('\r'))
        {
            out.push('\r');
        }
    }
    out
}

fn redact_request_line(line: &str) -> String {
    let mut parts = line.splitn(3, ' ');
    let Some(method) = parts.next() else {
        return line.to_string();
    };
    let Some(uri) = parts.next() else {
        return line.to_string();
    };
    let Some(rest) = parts.next() else {
        return line.to_string();
    };
    format!("{method} {} {rest}", redact_uri(uri))
}

fn redact_header_line(line: &str) -> String {
    let Some((name, value)) = line.split_once(':') else {
        return line.to_string();
    };
    let value_prefix_len = value.len() - value.trim_start().len();
    let value_prefix = &value[..value_prefix_len];
    let trimmed_value = &value[value_prefix_len..];
    let redacted = redact_header_value(name, trimmed_value);
    format!("{name}:{value_prefix}{redacted}")
}

fn redact_header_value(name: &str, value: &str) -> String {
    let name_lc = name.trim().to_ascii_lowercase();
    if name_lc == "cookie" || name_lc == "set-cookie" {
        return redact_kv_pairs(value, &[';']);
    }
    if name_lc == "authorization" || is_sensitive_name(name) {
        return redact_authorization_like(value);
    }
    value.to_string()
}

fn redact_authorization_like(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return REDACTION_MASK.to_string();
    }
    if let Some((scheme, _credential)) = trimmed.split_once(char::is_whitespace) {
        return format!("{scheme} {REDACTION_MASK}");
    }
    REDACTION_MASK.to_string()
}

fn redact_body(body: &str) -> String {
    if body.trim().is_empty() {
        return body.to_string();
    }
    if let Some(redacted) = redact_multipart_body_without_header(body) {
        return redacted;
    }
    if let Ok(mut value) = serde_json::from_str::<Value>(body) {
        redact_json_value(&mut value, false);
        return serde_json::to_string(&value).unwrap_or_else(|_| body.to_string());
    }
    if body.contains('=') {
        return redact_kv_pairs(body, &['&']);
    }
    body.to_string()
}

fn redact_json_value(value: &mut Value, force_redact: bool) {
    if force_redact {
        *value = Value::String(REDACTION_MASK.to_string());
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                redact_json_value(value, is_sensitive_name(key));
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json_value(item, false);
            }
        }
        _ => {}
    }
}

fn multipart_boundary_from_head(head: &str) -> Option<String> {
    for line in head.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("content-type") {
            continue;
        }
        let value = value.trim();
        if !value
            .split(';')
            .next()
            .unwrap_or(value)
            .trim()
            .eq_ignore_ascii_case("multipart/form-data")
        {
            return None;
        }
        return header_parameter(value, "boundary").map(str::to_string);
    }
    None
}

fn redact_multipart_body_without_header(body: &str) -> Option<String> {
    let first_line = body.lines().next()?;
    let first_line = first_line.strip_suffix('\r').unwrap_or(first_line);
    let boundary = first_line.strip_prefix("--")?;
    if boundary.is_empty() || boundary.ends_with("--") {
        return None;
    }
    redact_multipart_body(body, boundary)
}

fn redact_multipart_body(body: &str, boundary: &str) -> Option<String> {
    let marker = format!("--{boundary}");
    if find_boundary(body, &marker, 0).is_none() {
        return None;
    }

    let mut out = String::with_capacity(body.len());
    let mut cursor = 0usize;
    while let Some(marker_start) = find_boundary(body, &marker, cursor) {
        out.push_str(&body[cursor..marker_start]);

        let marker_line_end = line_end_inclusive(body, marker_start);
        out.push_str(&body[marker_start..marker_line_end]);

        if body[marker_start + marker.len()..].starts_with("--") {
            cursor = marker_line_end;
            continue;
        }

        let part_start = marker_line_end;
        let part_end = find_boundary(body, &marker, part_start).unwrap_or(body.len());
        out.push_str(&redact_multipart_part(&body[part_start..part_end]));
        cursor = part_end;
    }
    out.push_str(&body[cursor..]);
    Some(out)
}

fn find_boundary(body: &str, marker: &str, from: usize) -> Option<usize> {
    let mut search_from = from;
    while let Some(rel) = body[search_from..].find(marker) {
        let candidate = search_from + rel;
        if is_boundary_line(body, marker, candidate) {
            return Some(candidate);
        }
        search_from = candidate + marker.len();
    }
    None
}

fn is_boundary_line(body: &str, marker: &str, index: usize) -> bool {
    if index != 0 && body.as_bytes().get(index - 1) != Some(&b'\n') {
        return false;
    }
    let after = &body[index + marker.len()..];
    after.is_empty()
        || after.starts_with('\n')
        || after.starts_with("\r\n")
        || after.starts_with("--")
}

fn line_end_inclusive(input: &str, start: usize) -> usize {
    input[start..]
        .find('\n')
        .map_or(input.len(), |rel| start + rel + 1)
}

fn redact_multipart_part(part: &str) -> String {
    let (head, separator, body) = split_http_message(part);
    let Some(name) = multipart_part_name(head) else {
        return part.to_string();
    };
    if !is_sensitive_name(&name) {
        return part.to_string();
    }

    let suffix = if body.ends_with("\r\n") {
        "\r\n"
    } else if body.ends_with('\n') {
        "\n"
    } else {
        ""
    };
    format!("{head}{separator}{REDACTION_MASK}{suffix}")
}

fn multipart_part_name(head: &str) -> Option<String> {
    for line in head.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-disposition") {
            return header_parameter(value, "name").map(str::to_string);
        }
    }
    None
}

fn header_parameter<'a>(value: &'a str, parameter_name: &str) -> Option<&'a str> {
    value.split(';').skip(1).find_map(|segment| {
        let (name, value) = segment.trim().split_once('=')?;
        if name.trim().eq_ignore_ascii_case(parameter_name) {
            Some(unquote_header_parameter(value.trim()))
        } else {
            None
        }
    })
}

fn unquote_header_parameter(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
}

fn redact_kv_pairs(input: &str, separators: &[char]) -> String {
    let mut out = String::with_capacity(input.len());
    let mut start = 0usize;
    for (idx, ch) in input.char_indices() {
        if separators.contains(&ch) {
            out.push_str(&redact_kv_segment(&input[start..idx]));
            out.push(ch);
            start = idx + ch.len_utf8();
        }
    }
    out.push_str(&redact_kv_segment(&input[start..]));
    out
}

fn redact_kv_segment(segment: &str) -> String {
    let leading_ws_len = segment.len() - segment.trim_start().len();
    let leading_ws = &segment[..leading_ws_len];
    let rest = &segment[leading_ws_len..];
    let Some((key, _value)) = rest.split_once('=') else {
        return segment.to_string();
    };
    if is_sensitive_name(key.trim()) {
        format!("{leading_ws}{key}={REDACTION_MASK}")
    } else {
        segment.to_string()
    }
}

fn normalize_identifier(value: &str) -> String {
    value
        .trim()
        .trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | '`' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>'
            )
        })
        .replace(['_', '-', '.'], " ")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_query_values_are_masked_for_sensitive_names() {
        let redacted = redact_uri("/login?user=alice&password=hunter2&token=abc#frag");
        assert_eq!(
            redacted,
            "/login?user=alice&password=+++++&token=+++++#frag"
        );
    }

    #[test]
    fn percent_encoded_sensitive_names_are_masked() {
        let redacted = redact_uri("/login?senha=abc&c%C3%B3digo=123&safe=ok");
        assert_eq!(redacted, "/login?senha=+++++&c%C3%B3digo=+++++&safe=ok");
    }

    #[test]
    fn http_message_masks_query_cookie_authorization_and_form_body() {
        let payload = concat!(
            "POST /login?token=query-token HTTP/1.1\n",
            "Host: example.test\n",
            "Cookie: session=ok; password=cookie-secret\n",
            "Authorization: Bearer header-token\n",
            "\n",
            "user=alice&password=body-secret&safe=ok"
        );
        let redacted = redact_payload(payload);
        assert!(redacted.contains("POST /login?token=+++++ HTTP/1.1"));
        assert!(redacted.contains("Cookie: session=ok; password=+++++"));
        assert!(redacted.contains("Authorization: Bearer +++++"));
        assert!(redacted.contains("user=alice&password=+++++&safe=ok"));
        assert!(!redacted.contains("query-token"));
        assert!(!redacted.contains("cookie-secret"));
        assert!(!redacted.contains("header-token"));
        assert!(!redacted.contains("body-secret"));
    }

    #[test]
    fn json_body_masks_nested_sensitive_values() {
        let redacted = redact_payload(r#"{"user":"alice","auth":{"api_key":"k","password":123}}"#);
        assert!(redacted.contains(r#""user":"alice""#));
        assert!(redacted.contains(r#""api_key":"+++++""#));
        assert!(redacted.contains(r#""password":"+++++""#));
    }

    #[test]
    fn multipart_body_masks_sensitive_form_parts() {
        let payload = concat!(
            "POST /upload HTTP/1.1\r\n",
            "Content-Type: multipart/form-data; boundary=abc123\r\n",
            "\r\n",
            "--abc123\r\n",
            "Content-Disposition: form-data; name=\"user\"\r\n",
            "\r\n",
            "alice\r\n",
            "--abc123\r\n",
            "Content-Disposition: form-data; name=\"token\"\r\n",
            "\r\n",
            "upload-secret\r\n",
            "--abc123\r\n",
            "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "file-body\r\n",
            "--abc123--\r\n"
        );
        let redacted = redact_payload(payload);
        assert!(redacted.contains("name=\"user\"\r\n\r\nalice\r\n"));
        assert!(redacted.contains("name=\"token\"\r\n\r\n+++++\r\n"));
        assert!(redacted.contains("name=\"file\"; filename=\"a.txt\""));
        assert!(redacted.contains("file-body"));
        assert!(!redacted.contains("upload-secret"));
    }

    #[test]
    fn multipart_redaction_ignores_boundary_text_inside_part_content() {
        let body = concat!(
            "--abc123\r\n",
            "Content-Disposition: form-data; name=\"token\"\r\n",
            "\r\n",
            "first\r\n",
            "--abc123 is not a boundary\r\n",
            "last\r\n",
            "--abc123--\r\n"
        );
        let redacted = redact_payload(body);
        assert!(redacted.contains("name=\"token\"\r\n\r\n+++++\r\n"));
        assert!(!redacted.contains("first"));
        assert!(!redacted.contains("last"));
        assert!(!redacted.contains("is not a boundary"));
    }

    #[test]
    fn localized_sensitive_words_are_detected() {
        assert!(is_sensitive_name("mot_de_passe"));
        assert!(is_sensitive_name("contraseña"));
        assert!(is_sensitive_name("пароль"));
        assert!(is_sensitive_name("密钥"));
        assert!(is_sensitive_name("パスワード"));
    }
}
