use csv;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, DecryptionShare, PublicKeyShare},
};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use indicatif::{ProgressBar, ProgressStyle};
use rand::thread_rng;
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

#[derive(Debug)]
struct Sums {
    s_x: f64,
    s_y: f64,
    s_xx: f64,
    s_xy: f64,
}

impl Default for Sums {
    fn default() -> Self {
        Sums {
            s_x: 0.0,
            s_y: 0.0,
            s_xx: 0.0,
            s_xy: 0.0,
        }
    }
}

// The example demonstrates collaborative linear regression using the combination of
// Fully Homomorphic Encryption (FHE) and threshold cryptography (a multi-party computation).
// Fully Homomorphic Encryption allows us to perform operations on encrypted data, while
// threshold cryptography allows us to distribute the control of a secret key among multiple
// parties, such that the key can only be used when a sufficient number of parties cooperate.
//
// In this example, we'll simulate several parties coordinating to create a shared key,
// we'll then simulate several parties preprocessing their share of the data, encrypting that
// preprocessed data to the shared key, using FHE to sum the encrypted data together, and finally
// decrypting the result using the shared key. The data will be a set of points in 2D space,
// and the result will be a linear regression line that fits the data.

fn main() -> Result<(), Box<dyn Error>> {
    let pb: ProgressBar = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner());
    let main: Instant = Instant::now();

    println!("\n\x1b[1mPractical FHE Workshop: Linear Regression\x1b[0m");

    // The precision of the FHE computation
    // As BFV only deals with integers, we need to scale the floating point numbers
    // to integers. The precision is the number of decimal places we want to keep.
    // In this example, we're using 4 decimal places, so we multiply by 10^4.
    // Try changing this number to see how the system scales with the precision.
    let precision: f64 = 10.0_f64.powi(4);
    println!("  \x1b[1mPrecision:\x1b[0m\t\t{precision}");

    // The number of parties that will generate a shared key and decrypt the result.
    //
    // In production, this would be the number of independent entities that need to
    // collaborate to decrypt the result. In this example, we obviously control all
    // of the parties, but we'll still simulate the process.
    //
    // Try changing this number to see how the system scales with the number of parties.
    let num_parties: usize = 1000;
    println!("  \x1b[1mParties:\x1b[0m\t\t{num_parties}");

    // Set the parameters for the FHE scheme
    //
    // The degree of the polynomial, usually denoted as `n` in the literature,
    // it determines the size of the ciphertext. A larger degree increases the security,
    // but will also increase the computation and storage.
    let degree: usize = 2048;
    println!("  \x1b[1mDegree:\x1b[0m\t\t{degree}");

    // The plaintext modulus determines the size of the plaintext space. Quite literally, how
    // large the plaintexts you want to represent can be. Plaintexts are typically represented
    // as integers modulo this value. A larger plaintext modulus allows for larger plaintexts.
    // However, larger plaintext modulus also increase noise growth per operation,
    // which can limit the number of computations that can be performed on the ciphertexts.
    let plaintext_modulus: u64 = 1032193;
    println!("  \x1b[1mPlaintext Modulus:\x1b[0m\t{plaintext_modulus}");

    // The moduli are used to control the noise growth in the ciphertexts in a leveled FHE scheme,
    // using a technique called "modulus switching". Each modulus in the vector  is a large prime corresponding
    // to a level in the computation, and computations are performed modulo the current level's modulus.
    // A larger modulus allows for more computations, but also increases the computation and storage costs.
    //
    // Note: In this example, we're using a single modulus, so we're not making use of modulus switching.
    // This is possible because we're only performing addition over the ciphertexts, which leads to little
    // noise growth in the BFV encryption scheme. If our computation was also using multiplication, we would
    // need to use multiple moduli to manage the noise growth.
    let moduli: Vec<u64> = vec![0x3FFFFFFF000001];
    println!("  \x1b[1mModuli:\x1b[0m\t\t{:?}", moduli);

    // Encode the parameters for the BFV scheme
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
    // In a production environment, we would use some public source of randomness that all
    // of the parties agree on.
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
    // The public keys are aggregated to create a single public key that can be used to try_encrypt
    // the inputs. This is done by summing the public key shares together.
    //
    // Note: because the public key shares are generated using the same CRP, the public key
    // shares are compatible and can be summed together.
    //
    // Note: because the shared public key is the sum of the public key shares, the
    // the public key shares can be aggregated in any order. Meaning the public key shares can
    // be generated asynchronously and aggregated in parallel (although we're not doing that here).
    let pk: PublicKey = parties.iter().map(|p| p.pk_share.clone()).aggregate()?;

    // Read data
    // let file_path = "../../data/winequality_0.csv";
    // let mut rdr = csv::Reader::from_path(file_path)?;
    // let mut data: Vec<(f64, f64)> = Vec::new();
    // for result in rdr.records() {
    //     let record = result?;
    //     let x: f64 = record[0].parse()?;
    //     let y: f64 = record[1].parse()?;
    //     data.push((x, y));
    // }

    let mut datasets: Vec<Vec<(f64, f64)>> = Vec::new();

    // Iterate over the dataset file names
    for i in 0..4 {
        let file_path = format!("../../data/winequality_{}.csv", i);
        let mut rdr = csv::Reader::from_path(file_path)?;
        let mut data: Vec<(f64, f64)> = Vec::new();

        // Read each record and parse the values
        for result in rdr.records() {
            let record = result?;
            let x: f64 = record[0].parse()?;
            let y: f64 = record[1].parse()?;
            data.push((x, y));
        }

        // Add the dataset to the outer vector
        datasets.push(data);
    }

    // Preprocess the data
    let mut processed_data: Vec<Sums> = Vec::new();

    for data in &datasets {
        let mut sums = Sums::default();

        for &(x, y) in data {
            sums.s_x += x;
            sums.s_y += y;
            sums.s_xx += x * x;
            sums.s_xy += x * y;
        }

        processed_data.push(sums);
    }

    // Calculate expected results
    let mut aggregated_sums = Sums {
        s_x: 0.0,
        s_y: 0.0,
        s_xx: 0.0,
        s_xy: 0.0,
    };

    // Aggregate the sums across all datasets
    let mut total_n = 0.0;
    for (_, data) in datasets.iter().enumerate() {
        let n = data.len() as f64;
        total_n += n;

        for &(x, y) in data {
            aggregated_sums.s_x += x;
            aggregated_sums.s_y += y;
            aggregated_sums.s_xx += x * x;
            aggregated_sums.s_xy += x * y;
        }
    }

    // Encrypt the data
    pb.enable_steady_tick(Duration::from_millis(100));
    let encryption_timer: Instant = Instant::now();

    let results: Vec<_> = processed_data
        .par_iter()
        .map(|sums| {
            let pt: Plaintext = Plaintext::try_encode(
                &[
                    (sums.s_x * precision) as i64,
                    (sums.s_y * precision) as i64,
                    (sums.s_xx * precision) as i64,
                    (sums.s_xy * precision) as i64,
                ]
                .to_vec(),
                Encoding::poly(),
                &params,
            )
            .unwrap();

            let ct: Ciphertext = pk.try_encrypt(&pt, &mut thread_rng()).unwrap();

            Ok::<fhe::bfv::Ciphertext, std::io::Error>(ct)
        })
        .collect();

    let encrypted_data: Result<Vec<_>, _> = results.into_iter().collect();
    pb.finish_and_clear();
    println!(
        "  \x1b[1mEncryption Time:\x1b[0m\t{:#?}",
        encryption_timer.elapsed()
    );

    pb.enable_steady_tick(Duration::from_millis(100));
    let sum_timer: Instant = Instant::now();

    // Sum the encrypted data
    let mut sum: Ciphertext = Ciphertext::zero(&params);
    for ct in encrypted_data.unwrap().iter() {
        sum += ct;
    }
    let tally: Arc<Ciphertext> = Arc::new(sum);
    pb.finish_and_clear();
    println!("  \x1b[1mTallying time:\x1b[0m\t{:#?}", sum_timer.elapsed());

    // Decrypt the result
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
    let decrypted: Vec<u64> = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
    let decrypted_s_x: f64 = decrypted[0] as f64 / precision;
    let decrypted_s_y: f64 = decrypted[1] as f64 / precision;
    let decrypted_s_xx: f64 = decrypted[2] as f64 / precision;
    let decrypted_s_xy: f64 = decrypted[3] as f64 / precision;

    pb.finish_and_clear();
    println!(
        "  \x1b[1mDecryption Time:\x1b[0m\t{:#?}",
        decryption_timer.elapsed()
    );

    println!("  \x1b[1mExecution time:\x1b[0m\t{:#?}", main.elapsed());

    // Calculate the slope and intercept for the aggregated data
    let (expected_slope, expected_intercept) = calculate_slope_and_intercept(
        total_n,
        aggregated_sums.s_x,
        aggregated_sums.s_y,
        aggregated_sums.s_xx,
        aggregated_sums.s_xy,
    );

    println!(
        "  \x1b[1mExpected Sums:\x1b[0m\tS_x: {}, S_y: {}, S_xx: {}, S_xy: {}",
        aggregated_sums.s_x, aggregated_sums.s_y, aggregated_sums.s_xx, aggregated_sums.s_xy
    );
    println!(
        "  \x1b[1mExpected Results:\x1b[0m\tIntercept: {}, Slope: {}",
        expected_intercept, expected_slope
    );

    // Calculate the slope and intercept for the decrypted data
    let (decrypted_slope, decrypted_intercept) = calculate_slope_and_intercept(
        total_n,
        decrypted_s_x,
        decrypted_s_y,
        decrypted_s_xx,
        decrypted_s_xy,
    );

    println!(
        "  \x1b[1mDecrypted Sums:\x1b[0m\tS_x: {}, S_y: {}, S_xx: {}, S_xy: {}",
        decrypted_s_x, decrypted_s_y, decrypted_s_xx, decrypted_s_xy
    );
    println!(
        "  \x1b[1mDecrypted Results:\x1b[0m\tIntercept: {}, Slope: {}",
        decrypted_intercept, decrypted_slope
    );

    Ok(())
}

fn calculate_slope_and_intercept(
    total_n: f64,
    s_x: f64,
    s_y: f64,
    s_xx: f64,
    s_xy: f64,
) -> (f64, f64) {
    let slope = (total_n * s_xy - s_x * s_y) / (total_n * s_xx - s_x * s_x);
    let intercept = (s_y - slope * s_x) / total_n;
    (slope, intercept)
}
