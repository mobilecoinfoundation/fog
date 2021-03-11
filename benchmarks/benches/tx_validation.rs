// Copyright (c) 2018-2021 The MobileCoin Foundation

use consensus_enclave::ConsensusServiceSgxEnclave;
use consensus_enclave_api::WellFormedTxContext;
use consensus_service::{
    tx_manager::UntrustedInterfaces, validators::DefaultTxManagerUntrustedInterfaces,
};
use criterion::{criterion_group, criterion_main, Criterion};
use mc_common::ResponderId;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{
    account_keys::{AccountKey, PublicAddress},
    constants::MINIMUM_FEE,
    get_tx_out_shared_secret,
    onetime_keys::{recover_onetime_private_key, view_key_matches_output},
    tx::{Tx, TxOut},
    validation::TransactionValidationResult,
    BlockIndex,
};
use mc_transaction_std::{InputCredentials, TransactionBuilder};
use mc_util_from_random::FromRandom;
use rand::{rngs::StdRng, SeedableRng};
use std::{convert::TryFrom, env, path::PathBuf, str::FromStr, time::Duration};

fn is_valid(tx: &Tx, ledger: &LedgerDB) -> TransactionValidationResult<()> {
    let untrusted = DefaultTxManagerUntrustedInterfaces::new(ledger.clone());
    untrusted.is_valid(&WellFormedTxContext::from(tx))
}

pub fn full_valid_tx_validation_benchmark(c: &mut Criterion) {
    const ENCLAVE_FILE: &str = "../libconsensus-enclave.signed.so";
    let enclave_path = env::current_exe()
        .expect("Could not get the path of our executable")
        .with_file_name(ENCLAVE_FILE);
    let _enclave = ConsensusServiceSgxEnclave::new(
        enclave_path,
        &ResponderId::from_str("node:123").unwrap(),
        &ResponderId::from_str("node:123").unwrap(),
    );

    let sample_data_dir = env::var("ORIGIN_DATA_DIR").expect("ORIGIN_DATA_DIR environment variable is missing - please point it at a directory containing ledger and keys");

    let account_keys: Vec<AccountKey> =
        mc_util_keyfile::keygen::read_default_root_entropies(&format!("{}/keys", sample_data_dir))
            .unwrap()
            .iter()
            .map(AccountKey::from)
            .collect();
    assert_ne!(0, account_keys.len());

    let ledger = LedgerDB::open(PathBuf::from(format!("{}/ledger", sample_data_dir))).unwrap();
    let n_blocks = ledger.num_blocks().unwrap();
    assert_ne!(0, n_blocks);

    let mut rng: StdRng = SeedableRng::from_seed([79u8; 32]);

    let sender = account_keys[0].clone();
    let recipient = AccountKey::random(&mut rng);

    // Choose a TxOut to spend. The output of the last block should be unspent.
    let transactions = ledger.get_block_contents(n_blocks - 1).unwrap().outputs;
    let tx_stored = {
        // Need to scan transactions until we find one that matches the `sender` key.
        let view_key = sender.view_key();
        transactions
            .iter()
            .find(|tx| {
                view_key_matches_output(
                    &view_key,
                    &RistrettoPublic::try_from(&tx.outputs[0].target_key).unwrap(),
                    0 as u64,
                    &RistrettoPublic::try_from(&tx.public_key).unwrap(),
                )
            })
            .unwrap()
    };
    let tx_out = tx_stored.outputs[0].clone();

    // Tx to validate.
    let tx = create_transaction(
        &ledger,
        &tx_out,
        RistrettoPublic::try_from(&tx_stored.public_key).unwrap(),
        0,
        &sender,
        recipient.address(),
        n_blocks + 10,
        &mut rng,
    );

    // The actual benchmarks.
    c.bench_function("is_valid without enclave", |b| {
        b.iter(|| is_valid(&tx, &ledger).unwrap())
    });

    /*
    c.bench_function("is_valid with enclave", |b| {
        b.iter(|| {
            consensus_service::validators::is_valid_with_enclave(&tx, &enclave, &ledger).unwrap()
        })
    });
    */
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(30))
        .measurement_time(Duration::from_secs(60))
        .sample_size(20)
    ;
    targets = full_valid_tx_validation_benchmark
}
criterion_main!(benches);

// Utility methods

/// Creates a transaction that sends the full value of `tx_out` to a single
/// recipient.
///
/// # Arguments:
/// * `ledger` - A ledger containing `tx_out`.
/// * `tx_out` - The TxOut that will be spent.
/// * `tx_public_key` - The public key of the transaction that encloses
///   `tx_out`.
/// * `tx_output_index` - The index of `tx_out` within its enclosing
///   transaction.
/// * `sender` - The owner of `tx_out`.
/// * `recipient` - The recipient of the new transaction.
/// * `tombstone_block` - The tombstone block for the new transaction.
/// * `rng` - The randomness used by this function
pub fn create_transaction(
    ledger: &LedgerDB,
    tx_out: &TxOut,
    tx_public_key: RistrettoPublic,
    tx_output_index: u64,
    sender: &AccountKey,
    recipient: &PublicAddress,
    tombstone_block: BlockIndex,
    rng: &mut StdRng,
) -> Tx {
    let mut transaction_builder = TransactionBuilder::new();

    // The input to this transaction is a ring containing only `tx_out`.
    let ring: Vec<TxOut> = vec![tx_out.clone()];

    // Membership proof for `tx_out`.
    let membership_proof = {
        let index = ledger.get_tx_out_index_by_hash(&tx_out.hash()).unwrap();
        ledger.get_tx_out_proof_of_memberships(&[index]).unwrap()
    };

    let onetime_private_key = recover_onetime_private_key(
        &tx_public_key,
        tx_output_index,
        &sender.view_private_key,
        &sender.default_subaddress_spend_key(),
    );

    let input_credentials = InputCredentials::new(
        ring,
        vec![membership_proof],
        0,
        onetime_private_key,
        tx_public_key,
        tx_output_index as usize,
        sender.view_private_key,
        rng,
    )
    .unwrap();
    transaction_builder.add_input(input_credentials);

    // Output
    let shared_secret = get_tx_out_shared_secret(&sender.view_private_key, &tx_public_key);
    let (value, _blinding) = tx_out
        .amount
        .get_value(tx_output_index as u8, &shared_secret)
        .expect("Malformed amount");

    assert!(value >= MINIMUM_FEE);
    transaction_builder
        .add_output(value - MINIMUM_FEE, recipient, None, rng)
        .unwrap();

    // Tombstone block
    transaction_builder.set_tombstone_block(tombstone_block);

    // Build and return the transaction
    transaction_builder.build(rng).unwrap()
}
