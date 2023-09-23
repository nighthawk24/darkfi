use darkfi::{
    tx::Transaction,
    zk::{
        halo2::{Field, Value},
        Proof, Witness, ZkCircuit,
    },
    Result,
};
use darkfi_contract_test_harness::{init_logger, Holder, TestHarness};
use darkfi_money_contract::{
    client::transfer_v1::TransferCallBuilder, MoneyFunction, MONEY_CONTRACT_ZKAS_BURN_NS_V1,
    MONEY_CONTRACT_ZKAS_MINT_NS_V1,
};
use darkfi_sdk::{
    crypto::{contract_id::TIMELOCK_CONTRACT_ID, poseidon_hash, MONEY_CONTRACT_ID},
    pasta::pallas,
    ContractCall,
};
use darkfi_serial::Encodable;
use darkfi_timelock_contract::TimelockFunction;
use log::info;
use rand::rngs::OsRng;

#[test]
fn timelock_integration() -> Result<()> {
    smol::block_on(async {
        init_logger();

        // Current block height we're verifying on
        let mut current_slot = 0;

        // Holders this test will use
        const HOLDERS: [Holder; 2] = [Holder::Alice, Holder::Bob];

        // Initialize harness
        let mut th = TestHarness::new(&["money".to_string(), "timelock".to_string()]).await?;

        // Reference Alice & Bob's keypairs
        let alice_wallet_keypair = th.holders.get(&Holder::Alice).unwrap().keypair;
        let bob_wallet_keypair = th.holders.get(&Holder::Bob).unwrap().keypair;

        // Alice mints some arbitrary tokens to herself.
        info!("[Alice] Building ALICE token mint tx");
        let (token_mint_tx, token_mint_params) =
            th.token_mint(10000, &Holder::Alice, &Holder::Alice, None, None)?;

        // Execute the transaction for every participant
        for holder in &HOLDERS {
            info!("[{holder:?}] Executing ALICE token mint tx");
            th.execute_token_mint_tx(holder, &token_mint_tx, &token_mint_params, current_slot)
                .await?;
        }

        // Alice gathers the minted coin
        th.gather_owncoin(&Holder::Alice, &token_mint_params.output, None)?;
        // We take note of the token ID to use later
        let token_id = th.holders.get(&Holder::Alice).unwrap().unspent_money_coins[0].note.token_id;

        // Now Alice sends those tokens to Bob and applies a timelock to them.
        // This means Bob will receive the tokens, but will be unable to spend
        // them until a certain block height is reached.

        // We will build the transaction. First, we build `Money::Transfer`.
        let (mint_pk, mint_zkbin) =
            th.proving_keys.get(&MONEY_CONTRACT_ZKAS_MINT_NS_V1.to_string()).unwrap().clone();
        let (burn_pk, burn_zkbin) =
            th.proving_keys.get(&MONEY_CONTRACT_ZKAS_BURN_NS_V1.to_string()).unwrap().clone();

        // Our spend hook will point to the timelock contract,
        // and the user_data will specify a certain block height.
        // user_data_blind is random and used to obfuscate the height.
        let spend_hook = *TIMELOCK_CONTRACT_ID;
        let user_data = pallas::Base::from(5);
        let user_data_blind = pallas::Base::random(&mut OsRng);

        // Build the Money::Transfer call
        let alice_transfer_builder = TransferCallBuilder {
            keypair: alice_wallet_keypair,
            recipient: bob_wallet_keypair.public,
            value: 10000,
            token_id,
            rcpt_spend_hook: spend_hook.inner(),
            rcpt_user_data: user_data,
            rcpt_user_data_blind: user_data_blind,
            change_spend_hook: pallas::Base::ZERO,
            change_user_data: pallas::Base::ZERO,
            change_user_data_blind: pallas::Base::ZERO,
            coins: th.holders.get(&Holder::Alice).unwrap().unspent_money_coins.clone(),
            tree: th.holders.get(&Holder::Alice).unwrap().money_merkle_tree.clone(),
            mint_zkbin: mint_zkbin.clone(),
            mint_pk: mint_pk.clone(),
            burn_zkbin: burn_zkbin.clone(),
            burn_pk: burn_pk.clone(),
            clear_input: false,
        };

        let alice_transfer_debris = alice_transfer_builder.build()?;

        // We build the transfer transaction
        let mut data = vec![MoneyFunction::TransferV1 as u8];
        alice_transfer_debris.params.encode(&mut data)?;
        let calls = vec![ContractCall { contract_id: *MONEY_CONTRACT_ID, data }];
        let proofs = vec![alice_transfer_debris.proofs];
        let mut tx = Transaction { calls, proofs, signatures: vec![] };
        let sigs = tx.create_sigs(&mut OsRng, &alice_transfer_debris.signature_secrets)?;
        tx.signatures = vec![sigs];

        // Both Alice and Bob's blockchains execute the tx
        th.execute_transfer_tx(
            &Holder::Alice,
            &tx,
            &alice_transfer_debris.params,
            current_slot,
            true,
        )
        .await?;
        th.execute_transfer_tx(
            &Holder::Bob,
            &tx,
            &alice_transfer_debris.params,
            current_slot,
            true,
        )
        .await?;

        // Bob gathers the received coin
        th.gather_owncoin(&Holder::Bob, &alice_transfer_debris.params.outputs[0], None)?;

        // Bob will transfer the tokens back to Alice, so he creates a transfer tx
        let bob_user_data_blind = pallas::Base::random(&mut OsRng);

        let bob_transfer_builder = TransferCallBuilder {
            keypair: bob_wallet_keypair,
            recipient: alice_wallet_keypair.public,
            value: 10000,
            token_id,
            rcpt_spend_hook: pallas::Base::ZERO,
            rcpt_user_data: pallas::Base::ZERO,
            rcpt_user_data_blind: pallas::Base::ZERO,
            change_spend_hook: pallas::Base::ZERO,
            change_user_data: pallas::Base::ZERO,
            change_user_data_blind: bob_user_data_blind,
            coins: th.holders.get(&Holder::Bob).unwrap().unspent_money_coins.clone(),
            tree: th.holders.get(&Holder::Bob).unwrap().money_merkle_tree.clone(),
            mint_zkbin: mint_zkbin.clone(),
            mint_pk: mint_pk.clone(),
            burn_zkbin: burn_zkbin.clone(),
            burn_pk: burn_pk.clone(),
            clear_input: false,
        };

        let bob_transfer_debris = bob_transfer_builder.build()?;

        // Now since in `rcpt_spend_hook` and `rcpt_user_data` we have
        // enforced the timelock, we also have to build the Timelock::Unlock
        // call. This one is a bit simpler and we build it directly since there
        // is not much data to handle. It will use the params from the transfer
        // call and none of its own. However we must build a zk proof.
        let (unlock_pk, unlock_zkbin) = th.proving_keys.get(&"Unlock".to_string()).unwrap();

        // Bob will claim he's unlocking at block height 7
        current_slot = 7;
        let unlock_claim = pallas::Base::from(current_slot);

        // Construct the ZK public inputs
        let public_inputs =
            vec![unlock_claim, poseidon_hash([pallas::Base::from(5), bob_user_data_blind])];

        // Construct the ZK proof witnesses
        let prover_witnesses = vec![
            Witness::Base(Value::known(unlock_claim)),
            Witness::Base(Value::known(pallas::Base::from(5))),
            Witness::Base(Value::known(bob_user_data_blind)),
        ];

        // Create the ZK proof
        let circuit = ZkCircuit::new(prover_witnesses, unlock_zkbin);
        let proof = Proof::create(unlock_pk, &[circuit], &public_inputs, &mut OsRng)?;

        // We build the transfer transaction
        let mut calls = vec![];
        let mut proofs = vec![];

        let mut data = vec![MoneyFunction::TransferV1 as u8];
        bob_transfer_debris.params.encode(&mut data)?;
        calls.push(ContractCall { contract_id: *MONEY_CONTRACT_ID, data });
        proofs.push(bob_transfer_debris.proofs);

        let data = vec![TimelockFunction::Unlock as u8];
        calls.push(ContractCall { contract_id: *TIMELOCK_CONTRACT_ID, data });
        proofs.push(vec![proof]);

        let mut tx = Transaction { calls, proofs, signatures: vec![] };
        let sigs = tx.create_sigs(&mut OsRng, &bob_transfer_debris.signature_secrets)?;
        tx.signatures = vec![sigs, vec![]];

        // Alice executes the transaction
        th.execute_transfer_tx(
            &Holder::Alice,
            &tx,
            &alice_transfer_debris.params,
            current_slot,
            true,
        )
        .await?;

        Ok(())
    })
}
