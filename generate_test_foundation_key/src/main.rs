// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_account_keys::AccountKey;
use rand::{rngs::StdRng, SeedableRng};

fn main() {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
    let foundation_account_key = AccountKey::random(&mut rng);

    println!(
        "view_private_key = {:?}",
        foundation_account_key.view_private_key().as_ref() as &[u8]
    );

    println!(
        "spend_private_key = {:?}",
        foundation_account_key.spend_private_key().as_ref() as &[u8]
    );

    println!(
        "public_view_key = {:?}",
        foundation_account_key
            .default_subaddress()
            .view_public_key()
            .to_bytes()
    );

    println!(
        "public_spend_key = {:?}",
        foundation_account_key
            .default_subaddress()
            .spend_public_key()
            .to_bytes()
    );
}
