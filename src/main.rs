use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, DecryptionShare, PublicKeyShare},
};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use indicatif::{ProgressBar, ProgressStyle};
use rand::{distributions::Uniform, prelude::Distribution, thread_rng};
use rayon::prelude::*;
use std::{
    error::Error,
    sync::Arc,
    time::{Duration, Instant},
};

struct Party {
    sk_share: SecretKey,
    pk_share: PublicKeyShare,
}

fn main() -> Result<(), Box<dyn Error>> {
    let pb: ProgressBar = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner());
    let main: Instant = Instant::now();

    println!("\n\x1b[1mPractical FHE Workshop: Secret Ballot\x1b[0m");

    // The number of votes that will be cast.
    //
    // Try changing this number to see how the system scales with the number of voters.
    let num_votes: usize = 1000;
    println!("\t\x1b[1mVotes:\x1b[0m\t\t\t{num_votes}");

    // The number of parties that will generate a shared key and decrypt the result.
    //
    // In production, this would be the number of independent entities that need to
    // collaborate to decrypt the result. In this example, we obviously control all
    // of the parties, but we'll still simulate the process.
    //
    // Try changing this number to see how the system scales with the number of parties.
    let num_parties: usize = 10;
    println!("\t\x1b[1mParties:\x1b[0m\t\t{num_parties}");

    // Set the parameters for the FHE scheme

    // The degree of the polynomial modulus, usually denoted as `n` in the literature,
    // it determines the size of the ciphertext. A larger degree increases the security,
    // but will also increase the computation and storage.
    let degree: usize = 2048;
    println!("\t\x1b[1mDegree:\x1b[0m\t\t\t{degree}");

    // The plaintext modulus, usually denoted as `t` in the literature, it determines
    // the size of the plaintext space. Plaintexts are typically represented as integers
    // modulo this value. A larger plaintext modulus allows for larger plaintexts.
    // However, larger plaintext modulus also increase noise growth per operation,
    // which can limit the number of computations that can be performed on the ciphertexts.
    // In our case, each vote will be a single bit and we'll sum each vote to produce the tally.
    // The upper bound on the plaintext size is equal to the number of votes cast, so a plaintext
    // modulus of 1032193 is sufficient for a little over 1M votes.
    let plaintext_modulus: u64 = match num_votes {
        1..=999 => 1009,
        1000..=9999 => 10007,
        10000..=99999 => 100003,
        100000..=199999 => 200003,
        200000..=299999 => 300007,
        300000..=399999 => 400009,
        400000..=499999 => 500009,
        500000..=599999 => 600011,
        600000..=699999 => 700001,
        700000..=799999 => 800011,
        800000..=899999 => 900001,
        _ => 1032193,
    };
    println!("\t\x1b[1mPlaintext Modulus:\x1b[0m\t{plaintext_modulus}");

    // The moduli for the ciphertexts, usually denoted as `q` in the literature, are used to
    // control the noise in the ciphertexts, using a technique called "modulus switching".
    // Each modulus in the vector corresponds to a level in the computation, and computations
    // are performed modulo the current level's modulus. A larger modulus allows for more
    // computations, but also increases the computation and storage costs.
    let moduli: Vec<u64> = vec![0x3FFFFFFF000001];
    println!("\t\x1b[1mModuli:\x1b[0m\t\t\t{:?}", moduli);

    let params = bfv::BfvParametersBuilder::new()
        .set_degree(degree)
        .set_plaintext_modulus(plaintext_modulus)
        .set_moduli(&moduli)
        .build_arc()
        .unwrap();

    // Generate the Common Random Polynomial (CRP)
    //
    // The CRP is used by each of the party members to generate their public key shares.
    // In this example, we're just grabbing some randomness seeded by the system.
    // In a production environment, we need to ensure that no party can control or predict this randomness.
    let crp: CommonRandomPoly = CommonRandomPoly::new(&params, &mut thread_rng())?;

    // Create the parties and their keys
    //
    // Each party generates a secret key share and a public key share using the CRP.
    let parties: Vec<Party> = (0..num_parties)
        .into_par_iter()
        .map(|_| {
            let sk_share: SecretKey = SecretKey::random(&params, &mut thread_rng());
            let pk_share: PublicKeyShare =
                PublicKeyShare::new(&sk_share, crp.clone(), &mut thread_rng()).unwrap();
            Party { sk_share, pk_share }
        })
        .collect();

    // Aggregate the public keys
    //
    // The public keys are aggregated to create a single public key that can be used to encrypt
    // the votes. This is done by summing the public key shares together.
    //
    // Note: because the public key shares are generated using the same CRP, the public key
    // shares are compatible and can be summed together.
    //
    // Note: because the shared public key is the sum of the public key shares, the
    // the public key shares can be aggregated in any order. Meaning the public key shares can
    // be generated asynchronously and aggregated in parallel as keys are published.
    let pk: PublicKey = parties.iter().map(|p| p.pk_share.clone()).aggregate()?;

    // Create the plaintext votes
    //
    // Each voter will cast a 1 for yes or a 0 for no. We'll simulate this by generating
    // a random bit for each voter.
    let dist: Uniform<u64> = Uniform::new_inclusive(0, 1);
    let votes: Vec<u64> = (0..num_votes)
        .into_par_iter()
        .map(|_| dist.sample(&mut thread_rng()))
        .collect();

    // Encrypt the votes
    //
    // Each vote is encrypted using the shared public key.
    //
    // Note: In a production environment, the votes would be encrypted independently by each
    // of the voters and only the ciphertexts would be published.
    //
    // Note: encrypting votes is what takes the bulk of the execution time in this example.
    // In a production environment, this cost would be distributed across the voters.
    pb.enable_steady_tick(Duration::from_millis(100));
    let encryption_timer: Instant = Instant::now();
    let results: Vec<_> = votes
        .par_iter()
        .map(|vote| {
            let pt: Plaintext = Plaintext::try_encode(&[*vote], Encoding::poly(), &params).unwrap();
            let ct: Ciphertext = pk.try_encrypt(&pt, &mut thread_rng()).unwrap();
            Ok::<fhe::bfv::Ciphertext, std::io::Error>(ct)
        })
        .collect();

    let encrypted_votes: Result<Vec<_>, _> = results.into_iter().collect();
    pb.finish_and_clear();
    println!(
        "\t\x1b[1mTime to Encrypt Votes:\x1b[0m\t{:#?}",
        encryption_timer.elapsed()
    );

    pb.enable_steady_tick(Duration::from_millis(100));
    let tally_timer: Instant = Instant::now();
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
    pb.finish_and_clear();
    println!(
        "\t\x1b[1mTally Execution time:\x1b[0m\t{:#?}",
        tally_timer.elapsed()
    );

    // Decrypt the tally
    //
    // The tally is decrypted by each of the parties to produce a decryption share.
    // The decryption shares are then aggregated to produce the plaintext tally.
    //
    // Note: As with the public key shares, aggregation of the decryption shares simply involves
    // summing them together. This means the decryption shares can be aggregated in any order
    // and can be generated asynchronously and aggregated in parallel as shares are published.
    pb.enable_steady_tick(Duration::from_millis(100));
    let decryption_timer: Instant = Instant::now();
    let decryption_shares: Result<Vec<DecryptionShare>, _> = parties
        .par_iter()
        .map(|party| {
            let sh = DecryptionShare::new(&party.sk_share, &tally, &mut thread_rng()).unwrap();
            Ok::<fhe::mbfv::DecryptionShare, std::io::Error>(sh)
        })
        .collect();
    let pt: Plaintext = decryption_shares.unwrap().into_iter().aggregate()?;
    let tally_vec: Vec<u64> = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
    let tally_result: u64 = tally_vec[0];
    pb.finish_and_clear();
    println!(
        "\t\x1b[1mTally Decryption time:\x1b[0m\t{:#?}",
        decryption_timer.elapsed()
    );
    println!(
        "\t\x1b[1mTotal Execution time:\x1b[0m\t{:#?}",
        main.elapsed()
    );

    // Print the result
    println!(
        "\t\x1b[1mVote result:\x1b[0m\t\t{} / {}",
        tally_result, num_votes
    );
    pb.finish_and_clear();

    // Check that the results match the expected result
    // Note: this is not possible in production, since we would not know the plaintext inputs.

    let expected_tally: u64 = votes.par_iter().sum();
    assert_eq!(tally_result, expected_tally);

    Ok(())
}
