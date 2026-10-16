//! Minimal RFC 3339 timestamps (UTC seconds) for binding validity windows.
//!
//! Accepted: `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)`, years 1970–9999. The
//! value is the instant in Unix seconds (fractions truncated). Serialization is
//! canonical `YYYY-MM-DDTHH:MM:SSZ`.
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u64);

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
fn digits(s: &[u8]) -> Option<i64> {
    (!s.is_empty() && s.iter().all(u8::is_ascii_digit))
        .then(|| s.iter().fold(0i64, |a, b| a * 10 + i64::from(b - b'0')))
}
impl Timestamp {
    pub fn parse(text: &str) -> Option<Self> {
        let b = text.as_bytes();
        if b.len() < 20 || b.len() > 40 {
            return None;
        }
        if b[4] != b'-'
            || b[7] != b'-'
            || !matches!(b[10], b'T' | b't')
            || b[13] != b':'
            || b[16] != b':'
        {
            return None;
        }
        let (y, mo, d) = (digits(&b[0..4])?, digits(&b[5..7])?, digits(&b[8..10])?);
        let (h, mi, s) = (
            digits(&b[11..13])?,
            digits(&b[14..16])?,
            digits(&b[17..19])?,
        );
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let month_days = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        if !(1970..=9999).contains(&y)
            || !(1..=12).contains(&mo)
            || d < 1
            || d > month_days[(mo - 1) as usize]
            || h > 23
            || mi > 59
            || s > 59
        {
            return None;
        }
        let mut rest = &b[19..];
        if let Some(fraction) = rest.strip_prefix(b".") {
            let n = fraction.iter().take_while(|c| c.is_ascii_digit()).count();
            if n == 0 || n > 9 {
                return None;
            }
            rest = &fraction[n..];
        }
        let offset = match rest {
            [b'Z' | b'z'] => 0,
            [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
                let (oh, om) = (digits(&[*h1, *h2])?, digits(&[*m1, *m2])?);
                if oh > 23 || om > 59 {
                    return None;
                }
                let v = oh * 3600 + om * 60;
                if *sign == b'+' { v } else { -v }
            }
            _ => return None,
        };
        let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s - offset;
        u64::try_from(secs).ok().map(Timestamp)
    }
    pub fn format(self) -> String {
        let secs = self.0 as i64;
        let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
        let r = secs.rem_euclid(86_400);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            r / 3600,
            r % 3600 / 60,
            r % 60
        )
    }
}
impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.format())
    }
}
impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Timestamp::parse(&text)
            .ok_or_else(|| serde::de::Error::custom("invalid RFC 3339 timestamp"))
    }
}
#[cfg(test)]
mod tests {
    use super::Timestamp;
    #[test]
    fn rfc3339_round_trip_offsets_and_refusals() {
        assert_eq!(Timestamp::parse("1970-01-01T00:00:00Z"), Some(Timestamp(0)));
        assert_eq!(
            Timestamp::parse("2026-10-16T09:12:44Z").unwrap().format(),
            "2026-10-16T09:12:44Z"
        );
        assert_eq!(
            Timestamp::parse("2026-10-16T18:12:44.123+09:00"),
            Timestamp::parse("2026-10-16T09:12:44Z")
        );
        assert_eq!(
            Timestamp::parse("2024-02-29T00:00:00Z").unwrap().format(),
            "2024-02-29T00:00:00Z"
        );
        for bad in [
            "2023-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-10-16 09:12:44Z",
            "2026-10-16T09:12:44",
            "1969-12-31T23:59:59Z",
            "2026-10-16T24:00:00Z",
            "2026-10-16T09:12:44+0900",
        ] {
            assert_eq!(Timestamp::parse(bad), None, "{bad}");
        }
    }
}
