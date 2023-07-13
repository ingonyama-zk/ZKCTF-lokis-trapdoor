use std::env;

use lambdaworks_crypto::commitments::kzg::StructuredReferenceString;
use lambdaworks_math::{field::element::FieldElement, traits::IsRandomFieldElementGenerator, elliptic_curve::short_weierstrass::curves::bls12_381::default_types::{FrField, FrElement}};
use lambdaworks_plonk::{setup::setup, prover::Prover};

use lokidoor::{circuit::{circuit_common_preprocessed_input, circuit_witness}, G1Point, G2Point, KZG, ChallengeProofData, any_as_u8_slice};
pub struct TestRandomFieldGenerator;
impl IsRandomFieldElementGenerator<FrField> for TestRandomFieldGenerator {
    fn generate(&self) -> FrElement {
        FrElement::zero()
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Please provide values for x and y");
        return;
    }

    let x = FieldElement::from(args[1].parse::<u64>().unwrap());
    let y = FieldElement::from(args[2].parse::<u64>().unwrap());

    // This is the circuit for `ASSERT 0 == y ** 2 - x ** 3 - 4`
    let cpi = circuit_common_preprocessed_input();

    let srs = StructuredReferenceString::<G1Point, G2Point>::from_file("srs_8").unwrap();
            
    let kzg = KZG::new(srs.clone());
    let verifying_key = setup(&cpi.clone(), &kzg);

    let public_input = vec![x.clone(), y.clone()];
    let witness = circuit_witness(&x, &y);

    let random_generator = TestRandomFieldGenerator {};
    let prover = Prover::new(kzg.clone(), random_generator);
    let proof = prover.prove(&witness, &public_input, &cpi, &verifying_key);

    let proof_data = ChallengeProofData {
        x: x.clone(),
        y: y.clone(),
        proof,
    };
    let proof_bytes = unsafe { any_as_u8_slice(&proof_data) };
    let base64_string = base64::encode(proof_bytes);
    println!("This is your proof: {}\nYou can send it to the verifier at 44.203.113.160 4000", base64_string);
}