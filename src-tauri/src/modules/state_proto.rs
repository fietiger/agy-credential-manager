//! Minimal Protocol Buffers wire-format helpers for the Antigravity
//! "unified state sync" blobs stored in the desktop clients' `state.vscdb`.
//!
//! The encoding implemented here is interoperable with the format used by
//! Antigravity / Antigravity IDE (and reverse-engineered/documented by the
//! open-source Antigravity-Manager project, github.com/lbjlaq/Antigravity-Manager).
//! Only the small subset of protobuf needed for those blobs is implemented:
//! varints and length-delimited fields, no external protobuf dependency.

/// Encode a protobuf varint.
pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    while value >= 0x80 {
        buf.push((value & 0x7F | 0x80) as u8);
        value >>= 7;
    }
    buf.push(value as u8);
    buf
}

/// Read a protobuf varint at `offset`; returns (value, next_offset).
pub fn read_varint(data: &[u8], offset: usize) -> Result<(u64, usize), String> {
    let mut result = 0u64;
    let mut shift = 0;
    let mut pos = offset;
    loop {
        if pos >= data.len() {
            return Err("incomplete varint".to_string());
        }
        let byte = data[pos];
        result |= ((byte & 0x7F) as u64) << shift;
        pos += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err("varint too long".to_string());
        }
    }
    Ok((result, pos))
}

/// Skip one field body starting at `offset` (just after its tag).
pub fn skip_field(data: &[u8], offset: usize, wire_type: u8) -> Result<usize, String> {
    match wire_type {
        0 => Ok(read_varint(data, offset)?.1),
        1 => Ok(offset + 8),
        2 => {
            let (length, content_offset) = read_varint(data, offset)?;
            Ok(content_offset + length as usize)
        }
        5 => Ok(offset + 4),
        _ => Err(format!("unknown wire type {}", wire_type)),
    }
}

/// Encode a length-delimited field (wire type 2).
pub fn encode_len_delim_field(field_num: u32, data: &[u8]) -> Vec<u8> {
    let mut f = encode_varint(((field_num << 3) | 2) as u64);
    f.extend(encode_varint(data.len() as u64));
    f.extend_from_slice(data);
    f
}

/// Encode a string field (wire type 2).
pub fn encode_string_field(field_num: u32, value: &str) -> Vec<u8> {
    encode_len_delim_field(field_num, value.as_bytes())
}

/// Encode a varint field (wire type 0).
pub fn encode_varint_field(field_num: u32, value: u64) -> Vec<u8> {
    let mut f = encode_varint((field_num << 3) as u64);
    f.extend(encode_varint(value));
    f
}

/// Find the first length-delimited field with the given number.
pub fn find_field(data: &[u8], target_field: u32) -> Result<Option<Vec<u8>>, String> {
    let mut offset = 0;
    while offset < data.len() {
        let (tag, new_offset) = match read_varint(data, offset) {
            Ok(v) => v,
            Err(_) => break,
        };
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;
        if field_num == target_field && wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset)?;
            let end = content_offset + length as usize;
            if end > data.len() {
                return Err("field extends past end of data".to_string());
            }
            return Ok(Some(data[content_offset..end].to_vec()));
        }
        offset = skip_field(data, new_offset, wire_type)?;
    }
    Ok(None)
}

/// Find the first varint field (wire type 0) with the given number.
/// Used by read-back/decode paths and tests.
#[allow(dead_code)]
pub fn find_varint_field(data: &[u8], target_field: u32) -> Result<Option<u64>, String> {
    let mut offset = 0;
    while offset < data.len() {
        let (tag, new_offset) = match read_varint(data, offset) {
            Ok(v) => v,
            Err(_) => break,
        };
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;
        if field_num == target_field && wire_type == 0 {
            let (value, _) = read_varint(data, new_offset)?;
            return Ok(Some(value));
        }
        offset = skip_field(data, new_offset, wire_type)?;
    }
    Ok(None)
}

/// Find all length-delimited fields with the given number.
pub fn find_all_fields(data: &[u8], target_field: u32) -> Result<Vec<Vec<u8>>, String> {
    let mut results = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let (tag, new_offset) = match read_varint(data, offset) {
            Ok(v) => v,
            Err(_) => break,
        };
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;
        if field_num == target_field && wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset)?;
            let end = content_offset + length as usize;
            if end > data.len() {
                break;
            }
            results.push(data[content_offset..end].to_vec());
            offset = end;
        } else {
            offset = skip_field(data, new_offset, wire_type)?;
        }
    }
    Ok(results)
}

/// Create the `OAuthTokenInfo` message stored inside the unified state:
/// field 1 access_token, field 2 token_type ("Bearer"), field 3 refresh_token,
/// field 4 expiry (Timestamp: field 1 seconds, field 2 nanos=0),
/// field 5 id_token (optional), field 6 is_gcp_tos (only when true).
///
/// Compatibility note: for personal accounts (consumer email domains) the
/// GCP-TOS flag is forced off, matching what the official clients expect
/// when they refresh the token.
pub fn create_oauth_info(
    access_token: &str,
    refresh_token: &str,
    expiry: i64,
    is_gcp_tos: bool,
    id_token: Option<&str>,
    email: Option<&str>,
) -> Vec<u8> {
    let mut is_gcp_tos = is_gcp_tos;
    if is_gcp_tos {
        if let Some(email_str) = email {
            let lower = email_str.to_lowercase();
            let personal = [
                "@gmail.com",
                "@outlook.com",
                "@hotmail.com",
                "@qq.com",
                "@163.com",
            ]
            .iter()
            .any(|d| lower.ends_with(d));
            if personal {
                is_gcp_tos = false;
            }
        }
    }

    let mut info = Vec::new();
    info.extend(encode_string_field(1, access_token));
    info.extend(encode_string_field(2, "Bearer"));
    info.extend(encode_string_field(3, refresh_token));

    let mut timestamp = encode_varint((1 << 3) as u64);
    timestamp.extend(encode_varint(expiry as u64));
    timestamp.extend(encode_varint((2 << 3) as u64));
    timestamp.extend(encode_varint(0));
    info.extend(encode_len_delim_field(4, &timestamp));

    if let Some(it) = id_token {
        info.extend(encode_string_field(5, it));
    }
    if is_gcp_tos {
        info.extend(encode_varint_field(6, 1));
    }
    info
}

/// Create one entry of a unified-state "topic": a map entry
/// (field 1 = sentinel key, field 2 = row) wrapped as topic field 1.
/// The row holds field 1 = base64(payload).
pub fn create_unified_topic_entry(sentinel_key: &str, payload: &[u8]) -> Vec<u8> {
    use base64::{engine::general_purpose, Engine as _};
    let row = encode_string_field(1, &general_purpose::STANDARD.encode(payload));
    let entry = [
        encode_string_field(1, sentinel_key),
        encode_len_delim_field(2, &row),
    ]
    .concat();
    encode_len_delim_field(1, &entry)
}

/// Create a complete unified-state value (base64 of a one-entry topic),
/// as stored for keys like `antigravityUnifiedStateSync.userStatus`.
pub fn create_unified_state_entry(sentinel_key: &str, payload: &[u8]) -> String {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.encode(create_unified_topic_entry(sentinel_key, payload))
}

/// Create one topic entry whose row payload is stored verbatim instead of
/// base64-encoded. The clients use this for the JSON auth-state entry
/// (`authStateWithContextSentinelKey`), whose row holds plain JSON.
pub fn create_unified_topic_entry_raw(sentinel_key: &str, payload: &[u8]) -> Vec<u8> {
    let row = encode_len_delim_field(1, payload);
    let entry = [
        encode_string_field(1, sentinel_key),
        encode_len_delim_field(2, &row),
    ]
    .concat();
    encode_len_delim_field(1, &entry)
}

/// Read the raw (non-base64) payload of a topic entry, e.g. the JSON body of
/// `authStateWithContextSentinelKey`.
pub fn decode_unified_state_raw(value_b64: &str, sentinel_key: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};
    let topic = general_purpose::STANDARD.decode(value_b64).ok()?;
    for entry in find_all_fields(&topic, 1).ok()? {
        if unified_topic_entry_key(&entry).as_deref() != Some(sentinel_key) {
            continue;
        }
        let row = find_field(&entry, 2).ok()??;
        let payload = find_field(&row, 1).ok()?;
        return payload.filter(|p| !p.is_empty());
    }
    None
}

/// Build the JSON auth-state payload for the `oauthToken` topic.
///
/// The clients keep `{"state": "...", "context": {...}}` next to the token.
/// Unknown keys and context fields from `previous` are preserved, so a switch
/// only flips the state to `signedIn` and refreshes the project binding.
pub fn create_auth_state_payload(previous: Option<&[u8]>, project: &str) -> Vec<u8> {
    let mut doc: serde_json::Value = previous
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(raw).ok())
        .filter(|v: &serde_json::Value| v.is_object())
        .unwrap_or_else(|| serde_json::json!({ "state": "signedOut", "context": {} }));

    doc["state"] = serde_json::json!("signedIn");
    if !doc.get("context").map(|c| c.is_object()).unwrap_or(false) {
        doc["context"] = serde_json::json!({});
    }
    let project = project.trim();
    if !project.is_empty() {
        doc["context"]["project"] = serde_json::json!(project);
    }

    serde_json::to_vec(&doc).unwrap_or_else(|_| b"{\"state\":\"signedIn\"}".to_vec())
}

/// Extract the `state` field (`signedIn` / `signedOut` / ...) of an auth-state
/// payload.
pub fn auth_state_label(raw: &[u8]) -> Option<String> {
    let doc: serde_json::Value = serde_json::from_slice(raw).ok()?;
    doc.get("state")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

fn unified_topic_entry_key(entry: &[u8]) -> Option<String> {
    let key_bytes = find_field(entry, 1).ok()??;
    String::from_utf8(key_bytes).ok()
}

/// Remove the topic entry with the given sentinel key, preserving all
/// other entries byte-for-byte.
pub fn remove_unified_topic_entry(data: &[u8], target_key: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let start = offset;
        let (tag, new_offset) = read_varint(data, offset)?;
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;
        let next = skip_field(data, new_offset, wire_type)?;
        if field_num == 1 && wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset)?;
            let end = content_offset + length as usize;
            if end > data.len() {
                return Err("topic entry extends past end of data".to_string());
            }
            if unified_topic_entry_key(&data[content_offset..end]).as_deref() == Some(target_key) {
                offset = next;
                continue;
            }
        }
        result.extend_from_slice(&data[start..next]);
        offset = next;
    }
    Ok(result)
}

/// Decode the payload stored for `sentinel_key` inside a unified-state
/// value (the base64 string found in `state.vscdb`). Returns None when
/// the key or entry is absent or malformed.
pub fn decode_unified_state_payload(value_b64: &str, sentinel_key: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};
    let topic = general_purpose::STANDARD.decode(value_b64).ok()?;
    for entry in find_all_fields(&topic, 1).ok()? {
        if unified_topic_entry_key(&entry).as_deref() != Some(sentinel_key) {
            continue;
        }
        let row = find_field(&entry, 2).ok()??;
        let payload_b64 = find_field(&row, 1).ok()??;
        let payload_str = String::from_utf8(payload_b64).ok()?;
        return general_purpose::STANDARD.decode(payload_str.trim()).ok();
    }
    None
}

/// Minimal user-status payload: the email as string fields 3 and 7,
/// which is what the clients need to display/bind the account.
pub fn create_minimal_user_status_payload(email: &str) -> Vec<u8> {
    [encode_string_field(3, email), encode_string_field(7, email)].concat()
}

/// Extract the email from a user-status payload.
///
/// The layouts differ between clients: this app writes the address to fields
/// 3 and 7, while a client that signed in itself fills field 3 with the
/// account's display name and keeps the address in field 7. So field 7 wins,
/// and any other field that actually looks like an address is the fallback —
/// a plain "field 3" read would report a person's name instead of the email.
pub fn user_status_email(payload: &[u8]) -> Option<String> {
    let mut offset = 0;
    let mut fallback: Option<String> = None;

    while offset < payload.len() {
        let (tag, after_tag) = match read_varint(payload, offset) {
            Ok(v) => v,
            Err(_) => break,
        };
        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;

        if wire_type == 2 {
            let (length, content_offset) = match read_varint(payload, after_tag) {
                Ok(v) => v,
                Err(_) => break,
            };
            let end = content_offset + length as usize;
            if end > payload.len() {
                break;
            }
            if let Ok(text) = String::from_utf8(payload[content_offset..end].to_vec()) {
                if looks_like_email(&text) {
                    if field_num == 7 {
                        return Some(text);
                    }
                    if fallback.is_none() {
                        fallback = Some(text);
                    }
                }
            }
            offset = end;
        } else {
            match skip_field(payload, after_tag, wire_type) {
                Ok(next) => offset = next,
                Err(_) => break,
            }
        }
    }

    fallback
}

/// Cheap sanity check so profile strings (display name, avatar URL, plan name)
/// are not mistaken for the account address.
fn looks_like_email(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 5 || value.contains(char::is_whitespace) {
        return false;
    }
    match value.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
        }
        None => false,
    }
}

/// A unified-state stringValue payload (field 3), e.g. for the
/// enterprise GCP project id preference.
pub fn create_string_value_payload(value: &str) -> Vec<u8> {
    encode_string_field(3, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 16_777_216, u32::MAX as u64] {
            let enc = encode_varint(v);
            let (dec, next) = read_varint(&enc, 0).unwrap();
            assert_eq!(dec, v);
            assert_eq!(next, enc.len());
        }
    }

    #[test]
    fn oauth_info_layout_and_decode() {
        let info = create_oauth_info("access-123", "1//refresh", 1_800_000_000, false, None, None);
        assert_eq!(
            find_field(&info, 1).unwrap().as_deref(),
            Some(b"access-123".as_slice())
        );
        assert_eq!(
            find_field(&info, 2).unwrap().as_deref(),
            Some(b"Bearer".as_slice())
        );
        assert_eq!(
            find_field(&info, 3).unwrap().as_deref(),
            Some(b"1//refresh".as_slice())
        );
        // expiry timestamp: field 4 -> field 1 varint
        let ts = find_field(&info, 4).unwrap().unwrap();
        let (tag, off) = read_varint(&ts, 0).unwrap();
        assert_eq!(tag >> 3, 1);
        let (secs, _) = read_varint(&ts, off).unwrap();
        assert_eq!(secs, 1_800_000_000);
        // no id_token / gcp fields
        assert!(find_field(&info, 5).unwrap().is_none());
    }

    #[test]
    fn oauth_info_gcp_flag_rules() {
        // workspace account keeps the flag
        let info = create_oauth_info("a", "r", 1, true, None, Some("user@company.com"));
        assert_eq!(find_varint_field(&info, 6).unwrap(), Some(1));
        // personal gmail account: flag forced off for client refresh compat
        let info = create_oauth_info("a", "r", 1, true, None, Some("user@gmail.com"));
        assert_eq!(find_varint_field(&info, 6).unwrap(), None);
    }

    #[test]
    fn topic_entry_add_remove_roundtrip() {
        let mut topic = Vec::new();
        topic.extend(create_unified_topic_entry("otherKey", b"keep-me"));
        topic.extend(create_unified_topic_entry(
            "oauthTokenInfoSentinelKey",
            b"old-token-info",
        ));

        let cleaned = remove_unified_topic_entry(&topic, "oauthTokenInfoSentinelKey").unwrap();
        // other entry survives and can be decoded back
        let mut buf = cleaned.clone();
        buf.extend(create_unified_topic_entry(
            "oauthTokenInfoSentinelKey",
            b"new-token-info",
        ));
        use base64::{engine::general_purpose, Engine as _};
        let b64 = general_purpose::STANDARD.encode(&buf);
        assert_eq!(
            decode_unified_state_payload(&b64, "oauthTokenInfoSentinelKey").as_deref(),
            Some(b"new-token-info".as_slice())
        );
        assert_eq!(
            decode_unified_state_payload(&b64, "otherKey").as_deref(),
            Some(b"keep-me".as_slice())
        );
    }

    #[test]
    fn user_status_entry_roundtrip() {
        let payload = create_minimal_user_status_payload("someone@example.com");
        let value = create_unified_state_entry("userStatusSentinelKey", &payload);
        let decoded = decode_unified_state_payload(&value, "userStatusSentinelKey").unwrap();
        assert_eq!(
            user_status_email(&decoded).as_deref(),
            Some("someone@example.com")
        );
    }

    #[test]
    fn user_status_prefers_email_over_display_name() {
        // What a client that signed in by itself stores: field 3 is the display
        // name, field 7 is the address.
        let payload = [
            encode_string_field(3, "Nova Cheng"),
            encode_string_field(7, "nova.cheng81@example.com"),
            encode_string_field(38, "https://lh3.googleusercontent.com/a/abc"),
        ]
        .concat();
        assert_eq!(
            user_status_email(&payload).as_deref(),
            Some("nova.cheng81@example.com")
        );

        // Nothing address-like present: report nothing instead of a name.
        let payload = [
            encode_string_field(3, "Nova Cheng"),
            encode_string_field(7, "Google AI Pro"),
        ]
        .concat();
        assert_eq!(user_status_email(&payload), None);
    }

    #[test]
    fn auth_state_entry_is_raw_json() {
        use base64::{engine::general_purpose, Engine as _};

        let payload = create_auth_state_payload(None, "proj-1");
        assert_eq!(auth_state_label(&payload).as_deref(), Some("signedIn"));

        let value = general_purpose::STANDARD.encode(create_unified_topic_entry_raw(
            "authStateWithContextSentinelKey",
            &payload,
        ));
        let raw = decode_unified_state_raw(&value, "authStateWithContextSentinelKey").unwrap();
        assert_eq!(raw, payload);
        assert!(String::from_utf8(raw).unwrap().contains("proj-1"));
    }

    #[test]
    fn auth_state_payload_keeps_existing_context() {
        let previous = br#"{"state":"signedOut","context":{"project":"old","appealUrl":"x"}}"#;
        let payload = create_auth_state_payload(Some(previous), "");
        let doc: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(doc["state"], "signedIn");
        assert_eq!(doc["context"]["project"], "old");
        assert_eq!(doc["context"]["appealUrl"], "x");
    }
}
