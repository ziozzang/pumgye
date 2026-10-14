use pumgye_core::{Decision as D, GuardEvidence as G, Policy};
fn policy() -> Policy {
    serde_json::from_value(serde_json::json!({
 "version":1,"information_classes":["public","internal"],
 "services":{"orders":{"permissions":["read","write"],"require_guard":true,
 "roles":{"reader":{"permissions":["read"],"information_classes":["public"]},
 "writer":{"permissions":["write"],"information_classes":["internal"],"inherits":["reader"],"minimum_aal":2}},
 "users":{"u_reader":["reader"],"u_writer":["writer"]},
 "networks":[{"cidr":"192.0.2.0/24","roles":["writer"]},{"cidr":"192.0.2.7/32","roles":["guest"]},{"cidr":"2001:db8::/32","roles":["reader"]}]}}})).unwrap()
}
#[test]
fn identity_network_and_service_intersection() {
    let p = policy().compile().unwrap();
    let eval = |s, u, ip: &str, permission, class, aal, g| {
        p.evaluate(s, u, ip.parse().unwrap(), permission, class, aal, g)
    };
    assert_eq!(
        eval(
            "orders",
            "u_writer",
            "192.0.2.1",
            "write",
            "internal",
            2,
            G::EnforcedAllow
        ),
        D::Allow
    );
    assert_eq!(
        eval(
            "orders",
            "u_reader",
            "192.0.2.1",
            "write",
            "public",
            2,
            G::EnforcedAllow
        ),
        D::PermissionDenied
    );
    assert_eq!(
        eval(
            "orders",
            "u_reader",
            "192.0.2.1",
            "read",
            "internal",
            2,
            G::EnforcedAllow
        ),
        D::ClassDenied
    );
    assert_eq!(
        eval(
            "orders",
            "u_writer",
            "192.0.2.1",
            "read",
            "public",
            1,
            G::EnforcedAllow
        ),
        D::AssuranceDenied
    );
    assert_eq!(
        eval(
            "orders",
            "unassigned",
            "192.0.2.1",
            "read",
            "public",
            3,
            G::EnforcedAllow
        ),
        D::Guest
    );
    assert_eq!(
        eval(
            "other",
            "u_writer",
            "192.0.2.1",
            "read",
            "public",
            3,
            G::EnforcedAllow
        ),
        D::UnknownService
    );
    assert_eq!(
        eval(
            "orders",
            "u_writer",
            "192.0.2.7",
            "read",
            "public",
            3,
            G::EnforcedAllow
        ),
        D::PermissionDenied
    );
    assert_eq!(
        eval(
            "orders",
            "u_writer",
            "198.51.100.1",
            "read",
            "public",
            3,
            G::EnforcedAllow
        ),
        D::NetworkGuest
    );
    assert_eq!(
        eval(
            "orders",
            "u_writer",
            "2001:db8::1",
            "write",
            "public",
            3,
            G::EnforcedAllow
        ),
        D::PermissionDenied
    );
    assert_eq!(
        eval(
            "orders",
            "u_reader",
            "::ffff:192.0.2.1",
            "read",
            "public",
            2,
            G::EnforcedAllow
        ),
        D::Allow
    );
    assert_eq!(
        eval(
            "orders",
            "u_reader",
            "192.0.2.1",
            "unknown",
            "public",
            2,
            G::EnforcedAllow
        ),
        D::PermissionDenied
    );
    for evidence in [G::Observe, G::Unavailable] {
        assert_eq!(
            eval(
                "orders",
                "u_writer",
                "192.0.2.1",
                "read",
                "public",
                3,
                evidence
            ),
            D::GuardUnavailable
        );
    }
    assert_eq!(
        eval(
            "orders",
            "u_writer",
            "192.0.2.1",
            "read",
            "public",
            3,
            G::Deny
        ),
        D::GuardDenied
    );
}
#[test]
fn malformed_policies_never_publish() {
    let mut p = policy();
    p.services
        .get_mut("orders")
        .unwrap()
        .roles
        .get_mut("reader")
        .unwrap()
        .inherits
        .push("writer".into());
    assert!(p.compile().is_err());
    let mut p = policy();
    p.services
        .get_mut("orders")
        .unwrap()
        .users
        .insert("u_x".into(), vec!["guest".into(), "reader".into()]);
    assert!(p.compile().is_err());
    let mut p = policy();
    let duplicate = p.services["orders"].networks[0].clone();
    p.services
        .get_mut("orders")
        .unwrap()
        .networks
        .push(duplicate);
    assert!(p.compile().is_err());
    let mut p = policy();
    p.services
        .get_mut("orders")
        .unwrap()
        .roles
        .get_mut("reader")
        .unwrap()
        .permissions
        .push("undefined".into());
    assert!(p.compile().is_err());
    let mut p = policy();
    p.information_classes.push("public".into());
    assert!(p.compile().is_err());
}
#[test]
fn explicit_optional_network_gate_still_obeys_deny() {
    let mut p = policy();
    p.services.get_mut("orders").unwrap().require_guard = false;
    let p = p.compile().unwrap();
    assert_eq!(
        p.evaluate(
            "orders",
            "u_writer",
            "192.0.2.1".parse().unwrap(),
            "read",
            "public",
            2,
            G::Unavailable
        ),
        D::Allow
    );
    assert_eq!(
        p.evaluate(
            "orders",
            "u_writer",
            "192.0.2.1".parse().unwrap(),
            "read",
            "public",
            2,
            G::Deny
        ),
        D::GuardDenied
    );
}

#[test]
fn highest_right_bit_and_ipv6_specific_guest_override_survive_compilation() {
    let mut policy = policy();
    policy.information_classes = (0..64).map(|i| format!("class{i}")).collect();
    let service = policy.services.get_mut("orders").unwrap();
    service.permissions = (0..64).map(|i| format!("action{i}")).collect();
    service.roles.clear();
    service.roles.insert(
        "top".into(),
        pumgye_core::Role {
            permissions: vec!["action63".into()],
            information_classes: vec!["class63".into()],
            inherits: vec![],
            minimum_aal: 3,
        },
    );
    service.users = [("u_writer".into(), vec!["top".into()])].into();
    service.networks = vec![
        pumgye_core::Network {
            cidr: "2001:db8::/32".parse().unwrap(),
            roles: vec!["top".into()],
        },
        pumgye_core::Network {
            cidr: "2001:db8:1::/48".parse().unwrap(),
            roles: vec!["guest".into()],
        },
    ];
    let compiled = policy.compile().unwrap();
    let evaluate = |ip: &str, action, class, aal, evidence| {
        compiled.evaluate(
            "orders",
            "u_writer",
            ip.parse().unwrap(),
            action,
            class,
            aal,
            evidence,
        )
    };
    assert_eq!(
        evaluate("2001:db8:2::1", "action63", "class63", 3, G::EnforcedAllow),
        D::Allow
    );
    assert_eq!(
        evaluate("2001:db8:1::1", "action63", "class63", 3, G::EnforcedAllow),
        D::PermissionDenied
    );
    assert_eq!(
        evaluate("2001:db8:2::1", "action0", "class63", 3, G::EnforcedAllow),
        D::PermissionDenied
    );
    assert_eq!(
        evaluate("2001:db8:2::1", "action63", "class0", 3, G::EnforcedAllow),
        D::ClassDenied
    );
    assert_eq!(
        evaluate("2001:db8:2::1", "action63", "class63", 2, G::EnforcedAllow),
        D::AssuranceDenied
    );
    assert_eq!(
        evaluate("2001:db8:2::1", "action63", "class63", 4, G::EnforcedAllow),
        D::AssuranceDenied
    );
    for evidence in [G::Observe, G::Unavailable] {
        assert_eq!(
            evaluate("2001:db8:2::1", "action63", "class63", 3, evidence),
            D::GuardUnavailable
        );
    }
    policy.information_classes.push("overflow".into());
    assert!(policy.compile().is_err());
}

#[test]
fn canonical_host_index_preserves_guest_override_and_rejects_mapped_duplicates() {
    let mut policy = policy();
    policy
        .services
        .get_mut("orders")
        .unwrap()
        .networks
        .push(pumgye_core::Network {
            cidr: "2001:db8::7/128".parse().unwrap(),
            roles: vec!["guest".into()],
        });
    let compiled = policy.compile().unwrap();
    for ip in ["192.0.2.7", "::ffff:192.0.2.7", "2001:db8::7"] {
        assert_eq!(
            compiled.evaluate(
                "orders",
                "u_writer",
                ip.parse().unwrap(),
                "read",
                "public",
                3,
                G::EnforcedAllow
            ),
            D::PermissionDenied
        );
    }
    policy
        .services
        .get_mut("orders")
        .unwrap()
        .networks
        .push(pumgye_core::Network {
            cidr: "::ffff:192.0.2.7/128".parse().unwrap(),
            roles: vec!["reader".into()],
        });
    assert!(
        policy.compile().is_err(),
        "mapped duplicate must not replace guest with reader"
    );
}

#[test]
fn mixed_host_and_cidr_indexes_match_independent_longest_prefix_reference() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let mut policy = policy();
    let networks = &mut policy.services.get_mut("orders").unwrap().networks;
    networks.clear();
    for (cidr, role) in [("192.0.2.0/24", "writer"), ("2001:db8::/120", "writer")] {
        networks.push(pumgye_core::Network {
            cidr: cidr.parse().unwrap(),
            roles: vec![role.into()],
        });
    }
    for base in (0..256u32).step_by(16) {
        let role = if base % 32 == 0 { "guest" } else { "writer" };
        for cidr in [
            format!("192.0.2.{base}/28"),
            format!("2001:db8::{base:x}/124"),
        ] {
            networks.push(pumgye_core::Network {
                cidr: cidr.parse().unwrap(),
                roles: vec![role.into()],
            });
        }
        let inner = base + 4;
        for cidr in [
            format!("192.0.2.{inner}/30"),
            format!("2001:db8::{inner:x}/126"),
        ] {
            networks.push(pumgye_core::Network {
                cidr: cidr.parse().unwrap(),
                roles: vec!["writer".into()],
            });
        }
    }
    for host in (0..256u32).step_by(7) {
        let role = if host % 2 == 0 { "guest" } else { "writer" };
        for cidr in [
            format!("192.0.2.{host}/32"),
            format!("2001:db8::{host:x}/128"),
        ] {
            networks.push(pumgye_core::Network {
                cidr: cidr.parse().unwrap(),
                roles: vec![role.into()],
            });
        }
    }
    // Reference scans the source policy; it uses neither compiled index nor trie code.
    for reverse in [false, true] {
        if reverse {
            policy
                .services
                .get_mut("orders")
                .unwrap()
                .networks
                .reverse();
        }
        let compiled = policy.compile().unwrap();
        for host in 0..256u32 {
            let v4 = Ipv4Addr::new(192, 0, 2, host as u8);
            let v6 = Ipv6Addr::from(
                u128::from("2001:db8::".parse::<Ipv6Addr>().unwrap()) + u128::from(host),
            );
            for ip in [
                IpAddr::V4(v4),
                IpAddr::V6(v4.to_ipv6_mapped()),
                IpAddr::V6(v6),
            ] {
                let canonical = ip.to_canonical();
                let selected = policy.services["orders"]
                    .networks
                    .iter()
                    .filter(|network| network.cidr.contains(&canonical))
                    .max_by_key(|network| network.cidr.prefix_len())
                    .unwrap();
                let expected = if selected.roles == ["guest"] {
                    D::PermissionDenied
                } else {
                    D::Allow
                };
                assert_eq!(
                    compiled.evaluate(
                        "orders",
                        "u_writer",
                        ip,
                        "read",
                        "public",
                        3,
                        G::EnforcedAllow
                    ),
                    expected,
                    "address {ip}, reverse {reverse}"
                );
            }
        }
    }
}
