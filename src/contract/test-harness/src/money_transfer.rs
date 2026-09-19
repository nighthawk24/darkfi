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

use darkfi::{
    tx::{ContractCallLeaf, Transaction, TransactionBuilder},
    Result,
};
use darkfi_money_contract::{
    client::{transfer_v1::make_transfer_call, OwnCoin},
    model::{MoneyFeeParamsV1, MoneyTransferParamsV1, TokenId},
    MoneyFunction, MONEY_CONTRACT_ZKAS_BURN_NS_V1, MONEY_CONTRACT_ZKAS_MINT_NS_V1,
};
use darkfi_sdk::{crypto::contract_id::MONEY_CONTRACT_ID, ContractCall};
use darkfi_serial::Encodable;

use super::{Holder, TestHarness};

impl TestHarness {
    /// Create a `Money::Transfer` transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn transfer(
        &mut self,
        amount: u64,
        holder: &Holder,
        recipient: &Holder,
        owncoins: &[OwnCoin],
        token_id: TokenId,
        block_height: u32,
        half_split: bool,
    ) -> Result<(Transaction, (MoneyTransferParamsV1, Option<MoneyFeeParamsV1>), Vec<OwnCoin>)>
    {
        let wallet = self.wallet(holder);
        let rcpt = self.wallet(recipient).keypair.public;

        let (mint_pk, mint_zkbin) = self.proving_keys.get(MONEY_CONTRACT_ZKAS_MINT_NS_V1).unwrap();
        let (burn_pk, burn_zkbin) = self.proving_keys.get(MONEY_CONTRACT_ZKAS_BURN_NS_V1).unwrap();

        // Create the transfer call
        let (params, secrets, mut spent_coins) = make_transfer_call(
            wallet.keypair,
            rcpt,
            amount,
            token_id,
            owncoins.to_owned(),
            wallet.money_merkle_tree.clone(),
            None,
            None,
            mint_zkbin.clone(),
            mint_pk.clone(),
            burn_zkbin.clone(),
            burn_pk.clone(),
            half_split,
        )?;

        // Encode the call
        let mut data = vec![MoneyFunction::TransferV1 as u8];
        params.encode(&mut data)?;
        let call = ContractCall { contract_id: *MONEY_CONTRACT_ID, data };

        // Create the TransactionBuilder containing the `Transfer` call
        let mut tx_builder = TransactionBuilder::new(
            ContractCallLeaf::new(call, secrets.proofs, secrets.signature_secrets),
            vec![],
        )?;

        // If we have tx fees enabled, make an offering
        let mut fee_params = None;
        if self.verify_fees {
            let (_fee_call, spent_fee_coins, fee_call_params) =
                self.append_fee_call(holder, &mut tx_builder, block_height).await?;
            spent_coins.extend_from_slice(&spent_fee_coins);
            fee_params = Some(fee_call_params);
        }

        // Now build the actual transaction and sign it with all necessary keys.
        let tx = tx_builder.build_signed()?;

        Ok((tx, (params, fee_params), spent_coins))
    }

    /// Execute a `Money::Transfer` transaction for a given [`Holder`].
    ///
    /// Returns any found [`OwnCoin`]s
    pub async fn execute_transfer_tx(
        &mut self,
        holder: &Holder,
        tx: Transaction,
        call_params: &MoneyTransferParamsV1,
        fee_params: &Option<MoneyFeeParamsV1>,
        block_height: u32,
        append: bool,
    ) -> Result<Vec<OwnCoin>> {
        let wallet = self.wallet_mut(holder);

        wallet.add_transaction("money::transfer", tx, block_height).await?;

        // Always insert nullifiers into SMT (needed for state consistency)
        wallet.process_inputs(&call_params.inputs, holder);

        let mut found_owncoins = vec![];
        if append {
            found_owncoins.extend(wallet.process_outputs(&call_params.outputs, holder));
            found_owncoins.extend(wallet.process_fee(fee_params, holder));
        }

        Ok(found_owncoins)
    }
}
