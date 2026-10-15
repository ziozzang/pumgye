//! Staged, private SAR wire prerequisite. This module authenticates no caller,
//! selects no cluster, evaluates no grant and exposes no listener/capability.
use pumgye_core::kubernetes_authorization::{Attributes, Principal};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{collections::BTreeMap, fmt};

pub(super) const MAX_BODY: usize = 32 * 1024;
const MAX_DEPTH: usize = 16;
pub(super) const ALLOW: &[u8] = br#"{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","status":{"allowed":true,"denied":false,"reason":"native authorization allowed"}}"#;
pub(super) const DENY: &[u8] = br#"{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","status":{"allowed":false,"denied":true,"reason":"native authorization denied"}}"#;
#[derive(Debug, PartialEq, Eq)]
pub(super) struct BadRequest;
/// Supported carries untrusted API-server assertion metadata, never permission.
/// The authenticated listener must supply its fixed cluster to the SAME View.
// Bounded inline request (~264 bytes); avoid another per-request heap allocation
// merely to represent the empty explicit-denial variant. No global lint waiver.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq)]
pub(super) enum Decoded {
    Supported {
        principal: Principal,
        attributes: Attributes,
    },
    Deny,
}

// Decode once without losing duplicate keys (including escaped spellings).
// All errors are collapsed; never expose serde errors containing input text.
struct Bounded(usize);
impl<'de> DeserializeSeed<'de> for Bounded {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Bounded {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded unique JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.0 >= MAX_DEPTH {
            return Err(serde::de::Error::custom("JSON depth"));
        }
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Bounded(self.0 + 1))? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.0 >= MAX_DEPTH {
            return Err(serde::de::Error::custom("JSON depth"));
        }
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            values.insert(key, map.next_value_seed(Bounded(self.0 + 1))?);
        }
        Ok(Value::Object(values))
    }
}
fn only(map: &Map<String, Value>, keys: &[&str]) -> bool {
    map.keys().all(|k| keys.contains(&k.as_str()))
}
fn text(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}
fn atom(s: &str, empty: bool) -> bool {
    (empty || !s.is_empty())
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn string(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)?.as_str().map(str::to_owned)
}
fn default_string(map: &Map<String, Value>, key: &str) -> Option<String> {
    match map.get(key) {
        None => Some(String::new()),
        Some(v) => v.as_str().map(str::to_owned),
    }
}
fn strings(value: Option<&Value>, max: usize) -> Option<Vec<String>> {
    let Some(value) = value else {
        return Some(vec![]);
    };
    let array = value.as_array()?;
    if array.len() > max {
        return None;
    }
    let mut result = Vec::with_capacity(array.len());
    for item in array {
        let s = item.as_str()?;
        if !text(s) || result.iter().any(|v| v == s) {
            return None;
        }
        result.push(s.to_owned());
    }
    Some(result)
}
fn inert(root: &Map<String, Value>) -> bool {
    let metadata = match root.get("metadata") {
        None => true,
        Some(Value::Object(m)) => {
            only(m, &["creationTimestamp"]) && m.get("creationTimestamp").is_none_or(Value::is_null)
        }
        _ => false,
    };
    let status = match root.get("status") {
        None => true,
        Some(Value::Object(m)) => {
            only(m, &["allowed"]) && m.get("allowed").is_none_or(|v| v == &Value::Bool(false))
        }
        _ => false,
    };
    metadata && status
}
fn principal(spec: &Map<String, Value>) -> Option<Principal> {
    let user = string(spec, "user")?;
    if !text(&user) || user == "system:anonymous" {
        return None;
    }
    let uid = match spec.get("uid") {
        None => None,
        Some(Value::String(s)) if text(s) => Some(s.clone()),
        _ => return None,
    };
    let groups = strings(spec.get("groups"), 64)?;
    if groups.iter().any(|v| v == "system:unauthenticated") {
        return None;
    }
    let mut extra = BTreeMap::new();
    if let Some(value) = spec.get("extra") {
        let map = value.as_object()?;
        if map.len() > 32 {
            return None;
        }
        for (k, v) in map {
            if !text(k) {
                return None;
            }
            let vs = strings(Some(v), 8)?;
            if vs.is_empty() {
                return None;
            }
            extra.insert(k.clone(), vs);
        }
    }
    Some(Principal {
        user,
        uid,
        groups,
        extra,
    })
}
fn attributes(spec: &Map<String, Value>) -> Option<Attributes> {
    match (
        spec.get("resourceAttributes"),
        spec.get("nonResourceAttributes"),
    ) {
        (Some(Value::Object(m)), None) => {
            if !only(
                m,
                &[
                    "group",
                    "version",
                    "resource",
                    "subresource",
                    "namespace",
                    "name",
                    "verb",
                ],
            ) {
                return None;
            }
            let group = default_string(m, "group")?;
            let version = default_string(m, "version")?;
            let resource = default_string(m, "resource")?;
            let subresource = default_string(m, "subresource")?;
            let namespace = default_string(m, "namespace")?;
            let name = default_string(m, "name")?;
            let verb = default_string(m, "verb")?;
            if !atom(&group, true)
                || !atom(&version, false)
                || !atom(&resource, false)
                || !matches!(subresource.as_str(), "" | "status" | "scale")
                || !atom(&namespace, false)
                || !atom(&name, false)
                || !matches!(verb.as_str(), "get" | "update" | "patch" | "delete")
            {
                return None;
            }
            Some(Attributes::Resource {
                group,
                version,
                resource,
                subresource,
                namespace,
                name,
                verb,
            })
        }
        (None, Some(Value::Object(m))) => {
            if !only(m, &["path", "verb"]) {
                return None;
            }
            let path = string(m, "path")?;
            let verb = string(m, "verb")?;
            if !path.starts_with('/')
                || path.len() > 256
                || path.contains("//")
                || !path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
                || path.split('/').any(|s| matches!(s, "." | ".."))
                || !matches!(
                    verb.as_str(),
                    "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
                )
            {
                return None;
            }
            Some(Attributes::NonResource { path, verb })
        }
        _ => None,
    }
}
pub(super) fn decode(bytes: &[u8]) -> Result<Decoded, BadRequest> {
    if bytes.is_empty() || bytes.len() > MAX_BODY {
        return Err(BadRequest);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = Bounded(0)
        .deserialize(&mut deserializer)
        .map_err(|_| BadRequest)?;
    deserializer.end().map_err(|_| BadRequest)?;
    let root = value.as_object().ok_or(BadRequest)?;
    if root.get("apiVersion").and_then(Value::as_str) != Some("authorization.k8s.io/v1")
        || root.get("kind").and_then(Value::as_str) != Some("SubjectAccessReview")
    {
        return Err(BadRequest);
    }
    let spec = root
        .get("spec")
        .and_then(Value::as_object)
        .ok_or(BadRequest)?;
    if !only(root, &["apiVersion", "kind", "spec", "metadata", "status"])
        || !inert(root)
        || !only(
            spec,
            &[
                "user",
                "uid",
                "groups",
                "extra",
                "resourceAttributes",
                "nonResourceAttributes",
            ],
        )
    {
        return Ok(Decoded::Deny);
    }
    match (principal(spec), attributes(spec)) {
        (Some(principal), Some(attributes)) => Ok(Decoded::Supported {
            principal,
            attributes,
        }),
        _ => Ok(Decoded::Deny),
    }
}
#[cfg(test)]
#[path = "sar_wire_tests.rs"]
mod tests;
