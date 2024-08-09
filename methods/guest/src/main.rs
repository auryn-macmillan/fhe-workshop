use fhe::bfv::{BfvParameters, Ciphertext};
use fhe_traits::{Deserialize, DeserializeParametrized, Serialize};
use risc0_zkvm::guest::env;
use std::sync::Arc;

fn main() {
    // read the public input from the journal
    let encrypted_votes_bytes: Vec<Vec<u8>> = env::read();
    let param_bytes: Vec<u8> = env::read();

    // Deserialize the encrypted votes and the parameters
    let params = Arc::new(BfvParameters::try_deserialize(&param_bytes).unwrap());
    let encrypted_votes: Result<Vec<Ciphertext>, _> = encrypted_votes_bytes
        .iter()
        .map(|bytes| Ciphertext::from_bytes(bytes, &params))
        .collect();

    // Tally the votes
    //
    // The votes are tallied by summing the encrypted vote ciphertexts together.
    // The result is an encrypted tally of the votes.
    // This is the real magic of homomorphic encryption, we can perform operations on the
    // ciphertexts that correspond to operations on the plaintexts!
    let mut sum: Ciphertext = Ciphertext::zero(&params);
    for vote in encrypted_votes.unwrap().iter() {
        sum += vote;
    }
    let tally: Arc<Ciphertext> = Arc::new(sum);

    // write public tally to the journal
    env::commit(&tally.to_bytes());
}
