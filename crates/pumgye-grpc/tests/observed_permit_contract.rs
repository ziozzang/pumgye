use prost::Message;
use pumgye_grpc::v1::{
    ObservedPermitTimeReply, ObservedProjectionPermitReply, ProjectionPermitReply,
};

#[test]
fn observed_envelope_preserves_distinct_admission_retention_and_legacy_proof() {
    let report = ObservedPermitTimeReply {
        request_id: 19,
        receipt_sha256: vec![5; 32],
        clock_domain: "pobs1:11111111111111111111111111111111:policy".into(),
        owner_now_ms: 500,
        proof_remaining_ms: 700,
        remaining_ms: 90,
        policy_revision: 2,
        network_revision: 3,
        route_revision: 4,
        plan_revision: 5,
        cache_ttl_ms: 0,
    };
    let legacy = ProjectionPermitReply {
        request_id: 19,
        context: None,
        binding: None,
        receipt: vec![7; 146],
        cache_ttl_ms: 0,
    };
    let envelope = ObservedProjectionPermitReply {
        permit: Some(legacy.clone()),
        observation: Some(report.clone()),
    };
    let decoded =
        ObservedProjectionPermitReply::decode(envelope.encode_to_vec().as_slice()).unwrap();
    assert_eq!(
        decoded.permit.unwrap().encode_to_vec(),
        legacy.encode_to_vec()
    );
    assert_eq!(decoded.observation.unwrap(), report);
    // Stable tags 4/5/6 keep source ticks and the two budgets independent.
    let golden =
        ObservedPermitTimeReply::decode(&[0x20, 0xf4, 0x03, 0x28, 0xbc, 0x05, 0x30, 0x5a][..])
            .unwrap();
    assert_eq!(
        (
            golden.owner_now_ms,
            golden.proof_remaining_ms,
            golden.remaining_ms
        ),
        (500, 700, 90)
    );
}
