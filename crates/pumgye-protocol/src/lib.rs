//! PPG1: bounded persistent decisions. Authentication belongs to trusted transports.
use anyhow::{Result, ensure};
pub use pumgye_core::{Decision, GuardEvidence};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
pub const HELLO: &[u8; 4] = b"PPG1";
pub const ACK: &[u8; 4] = b"PPA1";
pub const MAX_QUERY: usize = 552;
pub const REPLY_SIZE: usize = 32;
#[derive(Clone, Copy, Debug)]
pub struct Query<'a> {
    pub request_id: u64,
    pub minimum_revision: u64,
    pub ip: IpAddr,
    pub aal: u8,
    pub guard: GuardEvidence,
    pub service_id: &'a str,
    pub subject: &'a str,
    pub permission: &'a str,
    pub information_class: &'a str,
}
impl<'a> Query<'a> {
    pub fn encode(&self, output: &mut [u8; MAX_QUERY]) -> Result<usize> {
        ensure!(self.aal <= 3, "invalid assurance");
        output.fill(0);
        output[0] = 1;
        output[1] = if self.ip.is_ipv4() { 4 } else { 6 };
        output[2] = self.aal;
        output[3] = match self.guard {
            GuardEvidence::EnforcedAllow => 0,
            GuardEvidence::Deny => 1,
            GuardEvidence::Observe => 2,
            GuardEvidence::Unavailable => 3,
        };
        output[4..12].copy_from_slice(&self.request_id.to_be_bytes());
        output[12..20].copy_from_slice(&self.minimum_revision.to_be_bytes());
        match self.ip {
            IpAddr::V4(ip) => output[20..24].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => output[20..36].copy_from_slice(&ip.octets()),
        }
        let mut cursor = 36;
        for value in [
            self.service_id,
            self.subject,
            self.permission,
            self.information_class,
        ] {
            ensure!(
                !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control),
                "invalid identifier"
            );
            output[cursor] = value.len() as u8;
            cursor += 1;
            output[cursor..cursor + value.len()].copy_from_slice(value.as_bytes());
            cursor += value.len();
        }
        Ok(cursor)
    }
    pub fn decode(input: &'a [u8]) -> Result<Self> {
        ensure!(
            (40..=MAX_QUERY).contains(&input.len()) && input[0] == 1 && input[2] <= 3,
            "invalid query frame"
        );
        let ip = match input[1] {
            4 => {
                ensure!(
                    input[24..36].iter().all(|b| *b == 0),
                    "invalid IPv4 padding"
                );
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&input[20..24])?))
            }
            6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&input[20..36])?)),
            _ => anyhow::bail!("invalid address family"),
        };
        let guard = match input[3] {
            0 => GuardEvidence::EnforcedAllow,
            1 => GuardEvidence::Deny,
            2 => GuardEvidence::Observe,
            3 => GuardEvidence::Unavailable,
            _ => anyhow::bail!("invalid guard evidence"),
        };
        let mut cursor = 36;
        let mut identifier = || -> Result<&'a str> {
            let len = *input
                .get(cursor)
                .ok_or_else(|| anyhow::anyhow!("missing identifier"))?
                as usize;
            cursor += 1;
            ensure!((1..=128).contains(&len), "invalid identifier size");
            let value = std::str::from_utf8(
                input
                    .get(cursor..cursor + len)
                    .ok_or_else(|| anyhow::anyhow!("truncated identifier"))?,
            )?;
            cursor += len;
            ensure!(!value.chars().any(char::is_control), "invalid identifier");
            Ok(value)
        };
        let (service_id, subject, permission, information_class) =
            (identifier()?, identifier()?, identifier()?, identifier()?);
        ensure!(cursor == input.len(), "query has trailing bytes");
        Ok(Self {
            request_id: u64::from_be_bytes(input[4..12].try_into()?),
            minimum_revision: u64::from_be_bytes(input[12..20].try_into()?),
            ip,
            aal: input[2],
            guard,
            service_id,
            subject,
            permission,
            information_class,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub request_id: u64,
    pub revision: u64,
    pub decision: Option<Decision>,
}
impl Reply {
    pub fn encode(self) -> [u8; REPLY_SIZE] {
        let mut out = [0; REPLY_SIZE];
        out[0] = 1;
        out[1] = match self.decision {
            Some(Decision::Allow) => 0,
            Some(Decision::UnknownService) => 1,
            Some(Decision::Guest) => 2,
            Some(Decision::NetworkGuest) => 3,
            Some(Decision::PermissionDenied) => 4,
            Some(Decision::ClassDenied) => 5,
            Some(Decision::AssuranceDenied) => 6,
            Some(Decision::GuardDenied) => 7,
            Some(Decision::GuardUnavailable) => 8,
            None => 255,
        };
        out[4..12].copy_from_slice(&self.request_id.to_be_bytes());
        out[12..20].copy_from_slice(&self.revision.to_be_bytes());
        out
    }
    pub fn decode(input: &[u8; REPLY_SIZE]) -> Result<Self> {
        ensure!(
            input[0] == 1
                && input[2..4]
                    .iter()
                    .chain(input[20..].iter())
                    .all(|b| *b == 0),
            "invalid reply"
        );
        let decision = match input[1] {
            0 => Some(Decision::Allow),
            1 => Some(Decision::UnknownService),
            2 => Some(Decision::Guest),
            3 => Some(Decision::NetworkGuest),
            4 => Some(Decision::PermissionDenied),
            5 => Some(Decision::ClassDenied),
            6 => Some(Decision::AssuranceDenied),
            7 => Some(Decision::GuardDenied),
            8 => Some(Decision::GuardUnavailable),
            255 => None,
            _ => anyhow::bail!("invalid decision"),
        };
        Ok(Self {
            request_id: u64::from_be_bytes(input[4..12].try_into()?),
            revision: u64::from_be_bytes(input[12..20].try_into()?),
            decision,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_roundtrip_and_adversarial_frames() {
        let q = Query {
            request_id: 42,
            minimum_revision: 7,
            ip: "192.0.2.7".parse().unwrap(),
            aal: 2,
            guard: GuardEvidence::EnforcedAllow,
            service_id: "orders",
            subject: "fixture",
            permission: "read",
            information_class: "internal",
        };
        let mut frame = [0; MAX_QUERY];
        let len = q.encode(&mut frame).unwrap();
        let decoded = Query::decode(&frame[..len]).unwrap();
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.ip, q.ip);
        for end in 0..len {
            assert!(Query::decode(&frame[..end]).is_err());
        }
        frame[len] = 0;
        assert!(Query::decode(&frame[..len + 1]).is_err());
        frame[24] = 1;
        assert!(Query::decode(&frame[..len]).is_err());
        let r = Reply {
            request_id: 42,
            revision: 7,
            decision: Some(Decision::Allow),
        };
        assert_eq!(Reply::decode(&r.encode()).unwrap(), r);
        let mut bad = r.encode();
        bad[20] = 1;
        assert!(Reply::decode(&bad).is_err());
        let mut bad = r.encode();
        bad[1] = 9;
        assert!(Reply::decode(&bad).is_err());
    }
}
