use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, DecryptionShare, PublicKeyShare},
};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use rand::{distributions::Uniform, prelude::Distribution, thread_rng};
use std::{error::Error, sync::Arc};

struct Party {
    sk_share: SecretKey,
    pk_share: PublicKeyShare,
}

fn main() -> Result<(), Box<dyn Error>> {
    // TODO: be able to succinctly explain what these are
    let degree: usize = 4096;
    let plaintext_modulus: u64 = 4096;
    let moduli: Vec<u64> = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

    let num_voters = 1000;
    let num_parties = 10;

    println!("# FHE Voting Workshop Example");
    println!("\tVotes: {num_voters}");
    println!("\tParties: {num_parties}");

    let params = bfv::BfvParametersBuilder::new()
        .set_degree(degree)
        .set_plaintext_modulus(plaintext_modulus)
        .set_moduli(&moduli)
        .build_arc()
        .unwrap();

    // TODO: know what this is 😅
    let crp: CommonRandomPoly = CommonRandomPoly::new(&params, &mut thread_rng())?;

    // Create the parties and their keys
    let mut parties: Vec<Party> = Vec::with_capacity(num_parties);
    for _ in 0..num_parties {
        let sk_share: SecretKey = SecretKey::random(&params, &mut thread_rng());
        let pk_share: PublicKeyShare =
            PublicKeyShare::new(&sk_share, crp.clone(), &mut thread_rng())?;
        parties.push(Party { sk_share, pk_share });
    }

    // Aggregate the public keys
    let pk: PublicKey = parties.iter().map(|p| p.pk_share.clone()).aggregate()?;

    // Create the plaintext votes
    let dist: Uniform<u64> = Uniform::new_inclusive(0, 1);
    let votes: Vec<u64> = (0..num_voters)
        .map(|_| dist.sample(&mut thread_rng()))
        .collect();

    // Encrypt the votes
    let mut encrypted_votes: Vec<Ciphertext> = Vec::with_capacity(num_voters);
    for vote in votes.iter() {
        let pt = Plaintext::try_encode(&[*vote], Encoding::poly(), &params)?;
        let ct = pk.try_encrypt(&pt, &mut thread_rng())?;
        encrypted_votes.push(ct);
    }

    // Tally the votes
    let mut sum = Ciphertext::zero(&params);
    for vote in encrypted_votes.iter() {
        sum += vote;
    }
    let tally: Arc<Ciphertext> = Arc::new(sum);

    // Decrypt the tally
    let mut decryption_shares: Vec<DecryptionShare> = Vec::with_capacity(num_parties);
    for party in parties {
        let sh = DecryptionShare::new(&party.sk_share, &tally, &mut thread_rng())?;
        decryption_shares.push(sh);
    }
    let pt: Plaintext = decryption_shares.into_iter().aggregate()?;
    let tally_vec: Vec<u64> = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
    let tally_result: u64 = tally_vec[0];

    println!("Vote result = {} / {}", tally_result, num_voters);

    let expected_tally = votes.iter().sum();
    assert_eq!(tally_result, expected_tally);

    // result = ((2*a + M - b) mod M) mod 2

    Ok(())
}
