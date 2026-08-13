use ed25519_dalek::{SigningKey, SIGNATURE_LENGTH};
use n0_future::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

use crate::{Authorizer, Capability, Delegation, Expires, OpaqueDelegation};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Rpc {
    Read,
    ReadWrite,
    All,
}

impl Capability for Rpc {
    fn permits(&self, other: &Self) -> bool {
        match (self, other) {
            (Rpc::All, _) => true,
            (Rpc::ReadWrite, Rpc::Read | Rpc::ReadWrite) => true,
            (Rpc::ReadWrite, _) => false,
            (Rpc::Read, Rpc::Read) => true,
            (Rpc::Read, _) => false,
        }
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn v2_token() -> OpaqueDelegation {
    Delegation::issuing_builder(&key(0), key(1).verifying_key(), &Rpc::ReadWrite)
        .sign(Expires::At(4_102_444_800))
        .into()
}

fn hexdump(s: &str) -> Vec<u8> {
    let hex: String = s
        .lines()
        .map(|line| line.split("//").next().unwrap())
        .flat_map(|hex| hex.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    hex::decode(hex).unwrap()
}

const V2_POSTCARD: &str = "
    02                                                               // version: v2
    3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 // issuer: key(0)
    8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c // audience: key(1)
    00                                                               // capability origin: issuer
    01 80ae99a40f                                                    // valid until: at 4102444800
    01 01                                                            // capability: 1 byte, Rpc::ReadWrite
    83461886f14cdfa8b2d60eaab3ce00098761aa2bbf8dd028820fd54211bf2cca // signature (v2 DST)
    ccfc635242760b1c1d0d1d1c98943556f725c1e2c7edcd94365660e5af929f06
";

const V2_NEVER: &str = "
    02                                                               // version: v2
    3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 // issuer: key(0)
    8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c // audience: key(1)
    00                                                               // capability origin: issuer
    00                                                               // valid until: never
    01 02                                                            // capability: 1 byte, Rpc::All
    272b3ed3ea9b4d0837c3a3fb4e7a1e234411f5febdaa32b35c499f168bc4199a // signature (v2 DST)
    7e2d4944846a0689ad5c6f89f9cff7283836f78633dd95e896aaa73fd28a490e
";

const V2_STRING: &str = "ai5wuj54z23killcuounaktpbvzwkmqvo4o6eq5ghlaerimllhnctcui4poxicprsx6vfwznhs5f24wkm4e36hmucin7g5eiag2a6324aaaybluzuqhqcamdiymin4km36ulfvqovkz44aajq5q2uk57rxicraqp2vbbdpzmzlgpyy2sij3awha5buorzgeugvlpojob4ld63tmugzlgbznpskpqm";

#[test]
fn wire_snapshots() {
    let v2 = v2_token();
    let bytes = v2.encode();
    assert_eq!(bytes[0], 2);
    assert_eq!(hex::encode(&bytes), hex::encode(hexdump(V2_POSTCARD)));
    assert_eq!(OpaqueDelegation::decode(&hexdump(V2_POSTCARD)).unwrap(), v2);

    assert_eq!(v2.issuer(), &key(0).verifying_key());
    assert_eq!(v2.audience(), &key(1).verifying_key());
    assert_eq!(v2.expires(), &Expires::At(4_102_444_800));
    assert_eq!(v2.capability_issuer(), &key(0).verifying_key());
    assert_eq!(v2.capability(), &[1]);

    let never: OpaqueDelegation =
        Delegation::issuing_builder(&key(0), key(1).verifying_key(), &Rpc::All)
            .sign(Expires::Never)
            .into();
    assert_eq!(hex::encode(never.encode()), hex::encode(hexdump(V2_NEVER)));
    assert_eq!(OpaqueDelegation::decode(&hexdump(V2_NEVER)).unwrap(), never);

    let typed = Delegation::<Rpc>::decode(&v2.encode()).unwrap();
    assert_eq!(typed.encode(), v2.encode());
    assert_eq!(typed.opaque(), &v2);
}

#[test]
fn string_snapshots() {
    let v2 = v2_token();
    assert_eq!(v2.encode_string(), V2_STRING);
    assert_eq!(OpaqueDelegation::decode_string(V2_STRING).unwrap(), v2);

    let typed = Delegation::<Rpc>::decode_string(V2_STRING).unwrap();
    assert_eq!(typed.opaque(), &v2);

    let mut bytes = data_encoding::BASE32_NOPAD
        .decode(V2_STRING.to_ascii_uppercase().as_bytes())
        .unwrap();
    let n = bytes.len();
    bytes[n - 1] ^= 1;
    let mut tampered = data_encoding::BASE32_NOPAD.encode(&bytes);
    tampered.make_ascii_lowercase();
    assert!(OpaqueDelegation::decode_string(&tampered).is_err());
}

#[test]
fn serde_delegates_to_encode() {
    let v2 = v2_token();
    let typed = Delegation::<Rpc>::decode(&v2.encode()).unwrap();

    let wire = postcard::to_stdvec(&v2).unwrap();
    assert_eq!(wire, postcard::to_stdvec(&v2.encode()).unwrap());
    assert_eq!(postcard::from_bytes::<OpaqueDelegation>(&wire).unwrap(), v2);
    assert_eq!(postcard::to_stdvec(&typed).unwrap(), wire);
    assert_eq!(
        postcard::from_bytes::<Delegation<Rpc>>(&wire).unwrap(),
        typed
    );

    let mut cbor = Vec::new();
    ciborium::into_writer(&v2, &mut cbor).unwrap();
    let mut expected = Vec::new();
    ciborium::into_writer(&v2.encode(), &mut expected).unwrap();
    assert_eq!(cbor, expected);
    assert_eq!(
        ciborium::from_reader::<OpaqueDelegation, _>(&cbor[..]).unwrap(),
        v2
    );

    let quoted = serde_json::to_string(&v2.encode_string()).unwrap();
    assert_eq!(serde_json::to_string(&v2).unwrap(), quoted);
    assert_eq!(
        serde_json::from_str::<OpaqueDelegation>(&quoted).unwrap(),
        v2
    );
    assert_eq!(
        serde_json::from_str::<Delegation<Rpc>>(&quoted).unwrap(),
        typed
    );
    assert_eq!(ron::to_string(&v2).unwrap(), quoted);
    assert_eq!(ron::from_str::<OpaqueDelegation>(&quoted).unwrap(), v2);
}

#[test]
fn v2_decode_rejects_tampering() {
    let issuer = key(0);
    let audience = key(1).verifying_key();
    let delegation: OpaqueDelegation = Delegation::issuing_builder(&issuer, audience, &Rpc::Read)
        .sign(Expires::Never)
        .into();
    let good = delegation.encode();

    let mut forged = good.clone();
    let n = forged.len();
    forged[n - SIGNATURE_LENGTH..].fill(0);
    assert!(OpaqueDelegation::decode(&forged).is_err());

    let mut widened = good.clone();
    let capability_offset = 1 + 32 + 32 + 1 + 1 + 1;
    assert_eq!(widened[capability_offset - 1], 1);
    assert_eq!(widened[capability_offset], 0);
    widened[capability_offset] = 2;
    assert!(OpaqueDelegation::decode(&widened).is_err());

    let mut padded = good.clone();
    let signature_start = padded.len() - SIGNATURE_LENGTH;
    padded.insert(signature_start, 0);
    assert!(OpaqueDelegation::decode(&padded).is_err());

    let mut versioned = good.clone();
    versioned[0] = 3;
    assert!(OpaqueDelegation::decode(&versioned).is_err());

    assert!(OpaqueDelegation::decode(&[]).is_err());
}

const V2_NC_EXPIRY: &str = "
    02                                                               // version: v2
    3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 // issuer: key(0)
    8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c // audience: key(1)
    00                                                               // capability origin: issuer
    01 80ae99a48f00                                                  // valid until: at 4102444800 (overlong varint)
    01 01                                                            // capability: 1 byte, Rpc::ReadWrite
    83461886f14cdfa8b2d60eaab3ce00098761aa2bbf8dd028820fd54211bf2cca // signature (over the canonical form)
    ccfc635242760b1c1d0d1d1c98943556f725c1e2c7edcd94365660e5af929f06
";
const V2_NC_CAP_LEN: &str = "
    02                                                               // version: v2
    3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 // issuer: key(0)
    8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c // audience: key(1)
    00                                                               // capability origin: issuer
    01 80ae99a40f                                                    // valid until: at 4102444800
    81 00 01                                                         // capability: len 1 (overlong 0x81 0x00), Rpc::ReadWrite
    83461886f14cdfa8b2d60eaab3ce00098761aa2bbf8dd028820fd54211bf2cca // signature (over the canonical form)
    ccfc635242760b1c1d0d1d1c98943556f725c1e2c7edcd94365660e5af929f06
";

#[test]
fn v2_rejects_non_canonical() {
    assert!(OpaqueDelegation::decode(&hexdump(V2_POSTCARD)).is_ok());
    for nc in [V2_NC_EXPIRY, V2_NC_CAP_LEN] {
        let err = OpaqueDelegation::decode(&hexdump(nc)).unwrap_err();
        assert!(
            err.to_string().contains("canonical"),
            "expected a non-canonical error, got: {err}"
        );
    }
}

#[test]
fn rejects_v1() {
    for lead in [0x01u8, 0x20u8] {
        let bytes = [lead; 8];
        let err = OpaqueDelegation::decode(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("v1"),
            "expected a v1 rejection, got: {err}"
        );
        assert!(Delegation::<Rpc>::decode(&bytes).is_err());
    }
}

#[test]
fn typed_delegation() {
    let issuer = key(0);
    let audience = key(1).verifying_key();

    let typed =
        Delegation::issuing_builder(&issuer, audience, &Rpc::ReadWrite).sign(Expires::Never);
    assert_eq!(typed.capability(), Rpc::ReadWrite);

    let untyped: OpaqueDelegation = typed.clone().into();
    let again = Delegation::<Rpc>::try_from(untyped.clone()).unwrap();
    assert_eq!(again, typed);

    #[derive(Debug, Serialize, Deserialize)]
    struct OtherVocabulary {
        topic: String,
        write: bool,
    }
    assert!(Delegation::<OtherVocabulary>::try_from(untyped.clone()).is_err());

    let wire = postcard::to_stdvec(&typed).unwrap();
    assert!(postcard::from_bytes::<Delegation<OtherVocabulary>>(&wire).is_err());

    let bob = key(2);
    let typed_link = Delegation::delegating_builder(
        &key(1),
        bob.verifying_key(),
        issuer.verifying_key(),
        &Rpc::Read,
    )
    .sign(Expires::Never);
    let root = Delegation::issuing_builder(&issuer, audience, &Rpc::All).sign(Expires::Never);
    let authorizer = Authorizer::new(issuer.verifying_key());
    authorizer
        .check_invocation_from(bob.verifying_key(), Rpc::Read, &[&root, &typed_link])
        .unwrap();
    assert!(authorizer
        .check_invocation_from(bob.verifying_key(), Rpc::ReadWrite, &[&root, &typed_link])
        .is_err());
}

#[test]
fn two_link_chain_invocation() {
    let service = key(0);
    let alice = key(1);
    let bob = key(2);

    let root: OpaqueDelegation =
        Delegation::issuing_builder(&service, alice.verifying_key(), &Rpc::All)
            .sign(Expires::At(4_102_444_800))
            .into();

    let link: OpaqueDelegation = Delegation::delegating_builder(
        &alice,
        bob.verifying_key(),
        service.verifying_key(),
        &Rpc::Read,
    )
    .sign(Expires::Never)
    .into();

    let authorizer = Authorizer::new(service.verifying_key());
    let chain = [&root, &link];
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    authorizer
        .check_opaque_invocation_from_at(now, bob.verifying_key(), Rpc::Read, &chain)
        .unwrap();
    assert!(authorizer
        .check_opaque_invocation_from_at(now, bob.verifying_key(), Rpc::ReadWrite, &chain)
        .is_err());
    assert!(authorizer
        .check_opaque_invocation_from_at(now, key(3).verifying_key(), Rpc::Read, &chain)
        .is_err());
    let late = SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_444_801);
    assert!(authorizer
        .check_opaque_invocation_from_at(late, bob.verifying_key(), Rpc::Read, &chain)
        .is_err());
}

#[test]
fn chain_must_start_at_the_authorizer() {
    let service = key(0);
    let alice = key(1);
    let bob = key(2);

    let alice_grant: OpaqueDelegation =
        Delegation::issuing_builder(&alice, bob.verifying_key(), &Rpc::All)
            .sign(Expires::Never)
            .into();
    let authorizer = Authorizer::new(service.verifying_key());
    assert!(authorizer
        .check_opaque_invocation_from(bob.verifying_key(), Rpc::Read, &[&alice_grant])
        .is_err());
}

#[test]
fn subject_must_be_the_authorizer() {
    let service = key(0);
    let other = key(1);
    let alice = key(2);

    let delegation: OpaqueDelegation = Delegation::delegating_builder(
        &service,
        alice.verifying_key(),
        other.verifying_key(),
        &Rpc::All,
    )
    .sign(Expires::Never)
    .into();
    let authorizer = Authorizer::new(service.verifying_key());
    assert!(authorizer
        .check_opaque_invocation_from(alice.verifying_key(), Rpc::Read, &[&delegation])
        .is_err());
}

#[test]
fn owner_needs_no_chain() {
    let service = key(0);
    let authorizer = Authorizer::new(service.verifying_key());
    authorizer
        .check_opaque_invocation_from(service.verifying_key(), Rpc::All, &[])
        .unwrap();
    assert!(authorizer
        .check_opaque_invocation_from(key(1).verifying_key(), Rpc::Read, &[])
        .is_err());
}
