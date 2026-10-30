/* This file is part of DarkFi (https://dark.fi)
 *
 * Copyright (C) 2020-2026 Dyne.org foundation
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::slice;

use darkfi::{
    tx::{ContractCallLeaf, Transaction, TransactionBuilder},
    zk::halo2::Field,
    Error, Result,
};
use darkfi_money_contract::{
    client::{
        compute_remainder_blind,
        fee_v1::{create_fee_proof, FeeCallInput, FeeCallOutput, FEE_CALL_GAS},
        money_call_nullifiers, MoneyNote, OwnCoin,
    },
    model::{token_id::DARK_TOKEN_ID, Input, MoneyFeeParamsV1, Output},
    MoneyFunction, MONEY_CONTRACT_ZKAS_FEE_NS_V1,
};
use darkfi_sdk::{
    blockchain::compute_fee,
    crypto::{
        contract_id::MONEY_CONTRACT_ID, note::AeadEncryptedNote, BaseBlind, Blind, FuncId,
        ScalarBlind, SecretKey,
    },
    pasta::pallas,
    ContractCall,
};
use darkfi_serial::Encodable;
use rand::rngs::OsRng;
use tracing::info;

use super::{Holder, TestHarness};

impl TestHarness {
    /// Create an empty transaction that includes a `Money::Fee` call.
    /// This is generally used to test the actual fee call, and also to
    /// see the gas usage of the call without other parts.
    pub async fn create_empty_fee_call(
        &mut self,
        holder: &Holder,
    ) -> Result<(Transaction, MoneyFeeParamsV1)> {
        let wallet = self.wallet(holder);

        // Compute fee call required fee
        let required_fee = compute_fee(&FEE_CALL_GAS);

        // Find a compatible OwnCoin
        let coin = wallet
            .unspent_money_coins
            .iter()
            .find(|x| x.note.token_id == *DARK_TOKEN_ID && x.note.value > required_fee)
            .unwrap();

        // Input and output setup
        let input = FeeCallInput {
            coin: coin.clone(),
            merkle_path: wallet.money_merkle_tree.witness(coin.leaf_position, 0).unwrap(),
            user_data_blind: Blind::random(&mut OsRng),
        };

        let output = FeeCallOutput {
            public_key: wallet.keypair.public,
            value: coin.note.value - required_fee,
            token_id: coin.note.token_id,
            blind: Blind::random(&mut OsRng),
            spend_hook: FuncId::none(),
            user_data: pallas::Base::ZERO,
        };

        // Generate blinding factors
        let token_blind = BaseBlind::random(&mut OsRng);
        let input_value_blind = ScalarBlind::random(&mut OsRng);
        let fee_value_blind = ScalarBlind::random(&mut OsRng);
        let output_value_blind = compute_remainder_blind(&[input_value_blind], &[fee_value_blind]);

        // Generate an ephemeral signing key
        let signature_secret = SecretKey::random(&mut OsRng);

        info!("Creating FeeV1 ZK proof");
        let (fee_pk, fee_zkbin) = self.proving_keys.get(MONEY_CONTRACT_ZKAS_FEE_NS_V1).unwrap();

        let (proof, public_inputs) = create_fee_proof(
            fee_zkbin,
            fee_pk,
            &input,
            input_value_blind,
            &output,
            output_value_blind,
            output.spend_hook,
            output.user_data,
            output.blind,
            token_blind,
            signature_secret,
        )?;

        // Encrypted note for the output
        let note = MoneyNote {
            coin_blind: output.blind,
            value: output.value,
            token_id: output.token_id,
            spend_hook: output.spend_hook,
            user_data: output.user_data,
            value_blind: output_value_blind,
            token_blind,
            memo: vec![],
        };

        let encrypted_note = AeadEncryptedNote::encrypt(&note, &output.public_key, &mut OsRng)?;

        let params = MoneyFeeParamsV1 {
            input: Input {
                value_commit: public_inputs.input_value_commit,
                token_commit: public_inputs.token_commit,
                nullifier: public_inputs.nullifier,
                merkle_root: public_inputs.merkle_root,
                user_data_enc: public_inputs.input_user_data_enc,
                signature_public: public_inputs.signature_public,
                tx_local: false,
            },
            output: Output {
                value_commit: public_inputs.output_value_commit,
                token_commit: public_inputs.token_commit,
                coin: public_inputs.output_coin,
                note: encrypted_note,
                tx_local: false,
            },
            fee_value_blind,
            token_blind,
        };

        let mut data = vec![MoneyFunction::FeeV1 as u8];
        required_fee.encode(&mut data)?;
        params.encode(&mut data)?;
        let call = ContractCall { contract_id: *MONEY_CONTRACT_ID, data };
        let mut tx_builder = TransactionBuilder::new(
            ContractCallLeaf::new(call, vec![proof], vec![signature_secret]),
            vec![],
        )?;
        let tx = tx_builder.build_signed()?;

        Ok((tx, params))
    }

    /// Execute the transaction created by `create_empty_fee_call()` for a given [`Holder`].
    ///
    /// Returns any found [`OwnCoin`]s.
    pub async fn execute_empty_fee_call_tx(
        &mut self,
        holder: &Holder,
        tx: Transaction,
        params: &MoneyFeeParamsV1,
        block_height: u32,
    ) -> Result<Vec<OwnCoin>> {
        let wallet = self.wallet_mut(holder);
        wallet.add_transaction("money::fee", tx, block_height).await?;
        Ok(wallet.process_fee(&Some(params.clone()), holder))
    }

    /// Updates a [`TransactionBuilder`] with fee payment for a given [`Holder`].
    ///
    /// Returns the call, spent coins, and fee params.
    pub async fn append_fee_call(
        &mut self,
        holder: &Holder,
        tx_builder: &mut TransactionBuilder,
        block_height: u32,
    ) -> Result<(ContractCall, Vec<OwnCoin>, MoneyFeeParamsV1)> {
        // First we verify the fee-less transaction to see how much gas it
        // uses for execution and verification.
        let wallet = self.wallet(holder);
        let validator = wallet.validator.read().await;
        let tx = tx_builder.build_signed()?;

        let gas_used = validator
            .add_test_transactions(
                slice::from_ref(&tx),
                block_height,
                validator.consensus.module.target,
                false,
                false,
            )
            .await?
            .0;

        // Compute the required fee
        let required_fee = compute_fee(&(gas_used + FEE_CALL_GAS));

        // Collect spent nullifiers from money calls
        let mut spent_nullifiers = vec![];
        for call in &tx.calls {
            if call.data.contract_id == *MONEY_CONTRACT_ID {
                if let Ok(nullifiers) = money_call_nullifiers(&call.data).await {
                    spent_nullifiers.extend(nullifiers);
                }
            }
        }

        // Find a suitable coin from wallet
        let mut coins = wallet.unspent_money_coins.clone();
        coins.retain(|x| {
            x.note.token_id == *DARK_TOKEN_ID &&
                x.note.value > required_fee &&
                !spent_nullifiers.contains(&x.nullifier())
        });
        if coins.is_empty() {
            return Err(Error::Custom("Not enough native tokens".to_string()));
        }
        let coin = &coins[0];
        let merkle_tree = &wallet.money_merkle_tree;

        let change_value = coin.note.value - required_fee;

        // Input and output setup
        let input = FeeCallInput {
            coin: coin.clone(),
            merkle_path: merkle_tree.witness(coin.leaf_position, 0).unwrap(),
            user_data_blind: BaseBlind::random(&mut OsRng),
        };

        let output = FeeCallOutput {
            public_key: wallet.keypair.public,
            value: change_value,
            token_id: coin.note.token_id,
            blind: BaseBlind::random(&mut OsRng),
            spend_hook: FuncId::none(),
            user_data: pallas::Base::ZERO,
        };

        // Create blinding factors
        let token_blind = BaseBlind::random(&mut OsRng);
        let input_value_blind = ScalarBlind::random(&mut OsRng);
        let fee_value_blind = ScalarBlind::random(&mut OsRng);
        let output_value_blind = compute_remainder_blind(&[input_value_blind], &[fee_value_blind]);

        // Create an ephemeral signing key
        let signature_secret = SecretKey::random(&mut OsRng);

        info!("Creating FeeV1 ZK proof");
        let (fee_pk, fee_zkbin) = self.proving_keys.get(MONEY_CONTRACT_ZKAS_FEE_NS_V1).unwrap();

        let (proof, public_inputs) = create_fee_proof(
            fee_zkbin,
            fee_pk,
            &input,
            input_value_blind,
            &output,
            output_value_blind,
            output.spend_hook,
            output.user_data,
            output.blind,
            token_blind,
            signature_secret,
        )?;

        // Encrypted note for the output
        let note = MoneyNote {
            coin_blind: output.blind,
            value: output.value,
            token_id: output.token_id,
            spend_hook: output.spend_hook,
            user_data: output.user_data,
            value_blind: output_value_blind,
            token_blind,
            memo: vec![],
        };

        let encrypted_note = AeadEncryptedNote::encrypt(&note, &output.public_key, &mut OsRng)?;

        let params = MoneyFeeParamsV1 {
            input: Input {
                value_commit: public_inputs.input_value_commit,
                token_commit: public_inputs.token_commit,
                nullifier: public_inputs.nullifier,
                merkle_root: public_inputs.merkle_root,
                user_data_enc: public_inputs.input_user_data_enc,
                signature_public: public_inputs.signature_public,
                tx_local: false,
            },
            output: Output {
                value_commit: public_inputs.output_value_commit,
                token_commit: public_inputs.token_commit,
                coin: public_inputs.output_coin,
                note: encrypted_note,
                tx_local: false,
            },
            fee_value_blind,
            token_blind,
        };

        // Encode the contract call
        let mut data = vec![MoneyFunction::FeeV1 as u8];
        required_fee.encode(&mut data)?;
        params.encode(&mut data)?;
        let call = ContractCall { contract_id: *MONEY_CONTRACT_ID, data };

        // Append the fee call to the transaction builder
        tx_builder.append(
            ContractCallLeaf::new(call.clone(), vec![proof], vec![signature_secret]),
            vec![],
        )?;

        Ok((call, vec![coin.clone()], params))
    }
}
