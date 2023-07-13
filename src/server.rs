use lambdaworks_crypto::commitments::kzg::StructuredReferenceString;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_plonk::{verifier::Verifier, setup::setup};

use crate::{KZG, G1Point, G2Point, circuit::circuit_common_preprocessed_input, ChallengeProofData, u8_slice_as_any};

pub const FLAG: &str = "ZKCTF{THIS_IS_NOT_A_FLAG}";


pub fn server_endpoint_verify(proof_bytes: &[u8]) -> String {
    let data: &ChallengeProofData = unsafe { u8_slice_as_any::<ChallengeProofData>(proof_bytes) };
    let common_preprocessed_input = circuit_common_preprocessed_input();
    let srs = StructuredReferenceString::<G1Point, G2Point>::from_file("srs_8").unwrap();
    let public_input = [data.x.clone(), data.y.clone()];
    let kzg = KZG::new(srs);
    let vk = setup(&common_preprocessed_input.clone(), &kzg);

    let verifier = Verifier::new(kzg);
    let result = verifier.verify(&data.proof, &public_input, &common_preprocessed_input, &vk);
    if !result {
        "Invalid Proof".to_string()
    } else if data.x != FieldElement::one() {
        "Valid Proof. Congrats! But x should equal to 1 in order to unlock the trapdoor".to_string()
    } else {
        FLAG.to_string()
    }
}