use lambdaworks_crypto::commitments::{kzg::{StructuredReferenceString, KateZaveruchaGoldberg}, traits::IsCommitmentScheme};
use lambdaworks_math::{elliptic_curve::{traits::IsEllipticCurve, short_weierstrass::curves::bls12_381::{pairing::BLS12381AtePairing, default_types::{FrElement, FrField}, curve::BLS12381Curve, twist::BLS12381TwistCurve}}, cyclic_group::IsGroup};
use lambdaworks_plonk::{setup::{VerificationKey, CommonPreprocessedInput}, prover::Proof};

pub mod circuit;
pub mod server;

pub const ORDER_8_ROOT_UNITY: FrElement = FrElement::from_hex_unchecked(
    "345766f603fa66e78c0625cd70d77ce2b38b21c28713b7007228fd3397743f7a",
); // order 8

pub const ORDER_R_MINUS_1_ROOT_UNITY: FrElement = FrElement::from_hex_unchecked("7");
pub type ChallengeCS = KateZaveruchaGoldberg<FrField, BLS12381AtePairing>;
pub type ChallengeVK = VerificationKey<<ChallengeCS as IsCommitmentScheme<FrField>>::Commitment>;
pub type ChallengeProof = Proof<FrField, ChallengeCS>;
pub type Pairing = BLS12381AtePairing;
pub type KZG = KateZaveruchaGoldberg<FrField, Pairing>;
pub type CPI = CommonPreprocessedInput<FrField>;
pub type G1Point = <BLS12381Curve as IsEllipticCurve>::PointRepresentation;
pub type G2Point = <BLS12381TwistCurve as IsEllipticCurve>::PointRepresentation;

pub struct ChallengeProofData {
    pub x: FrElement,
    pub y: FrElement,
    pub proof: ChallengeProof,
}

/// Generates a test SRS for the BLS12381 curve
/// n is the number of constraints in the system.
#[allow(unused)]
pub fn generate_srs(n: usize, secret: u64) -> StructuredReferenceString<G1Point, G2Point> {
    let s = FrElement::from(secret);
    let g1 = <BLS12381Curve as IsEllipticCurve>::generator();
    let g2 = <BLS12381TwistCurve as IsEllipticCurve>::generator();

    let powers_main_group: Vec<G1Point> = (0..n + 3)
        .map(|exp| g1.operate_with_self(s.pow(exp as u64).representative()))
        .collect();
    let powers_secondary_group = [g2.clone(), g2.operate_with_self(s.representative())];

    StructuredReferenceString::new(&powers_main_group, &powers_secondary_group)
}

pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::core::mem::size_of::<T>(),
    )
}

pub unsafe fn u8_slice_as_any<T>(p: &[u8]) -> &T {
    assert_eq!(p.len(), ::core::mem::size_of::<T>());
    &*(p.as_ptr() as *const T)
}