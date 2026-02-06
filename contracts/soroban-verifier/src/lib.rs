#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use soroban_sdk::{contract, contractimpl, Bytes, Env};
use ultrahonk_rust_verifier::UltraHonkVerifier;

const LIMB_BYTES: usize = 32;

#[contract]
pub struct UltraHonkSorobanVerifier;

#[contractimpl]
impl UltraHonkSorobanVerifier {
    /// Verifies an UltraHonk proof using an in-contract verifier.
    ///
    /// * `vk_json` – raw bytes of the `vk_fields.json` string emitted by `bb write_vk`.
    /// * `proof` – the `proof` file produced by `bb prove` (raw bytes, not hex encoded).
    /// * `public_inputs` – concatenated public input bytes as emitted by `bb prove`.
    ///
    /// Returns `true` when the proof is valid for the verification key and public inputs,
    /// otherwise returns `false`. Invalid encodings will cause a contract panic.
    pub fn verify(_env: Env, vk_json: Bytes, proof: Bytes, public_inputs: Bytes) -> bool {
        let vk = parse_vk_json(&vk_json);
        let proof_bytes = proof.to_alloc_vec();
        let public_inputs_chunks = split_public_inputs(&public_inputs.to_alloc_vec());

        let verifier = UltraHonkVerifier::new_from_json(&vk);
        verifier.verify(&proof_bytes, &public_inputs_chunks).is_ok()
    }
}

fn parse_vk_json(bytes: &Bytes) -> String {
    String::from_utf8(bytes.to_alloc_vec()).expect("vk_json must be valid UTF-8")
}

fn split_public_inputs(bytes: &[u8]) -> Vec<Vec<u8>> {
    assert!(
        bytes.len() % LIMB_BYTES == 0,
        "public inputs must be 32-byte aligned"
    );
    bytes
        .chunks(LIMB_BYTES)
        .map(|chunk| chunk.to_vec())
        .collect()
}