/* This file is part of DarkFi (https://dark.fi)
 *
 * Copyright (C) 2020-2025 Dyne.org foundation
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

use std::{collections::HashMap, str::FromStr};

use lazy_static::lazy_static;
use num_bigint::BigUint;
use rand::rngs::OsRng;
use rusqlite::types::Value;

use darkfi::{
    tx::Transaction,
    validator::fees::compute_fee,
    zk::{halo2::Field, proof::ProvingKey, vm::ZkCircuit, vm_heap::empty_witnesses, Proof},
    zkas::ZkBinary,
    Error, Result,
};
use darkfi_money_contract::{
    client::{
        compute_remainder_blind,
        fee_v1::{create_fee_proof, FeeCallInput, FeeCallOutput, FEE_CALL_GAS},
        MoneyNote, OwnCoin,
    },
    model::{
        Coin, Input, MoneyAuthTokenFreezeParamsV1, MoneyAuthTokenMintParamsV1, MoneyFeeParamsV1,
        MoneyGenesisMintParamsV1, MoneyPoWRewardParamsV1, MoneyTokenMintParamsV1,
        MoneyTransferParamsV1, Nullifier, Output, TokenId, DARK_TOKEN_ID,
    },
    MoneyFunction, MONEY_CONTRACT_ZKAS_FEE_NS_V1,
};
use darkfi_sdk::{
    bridgetree,
    crypto::{
        note::AeadEncryptedNote,
        pasta_prelude::PrimeField,
        smt::{PoseidonFp, EMPTY_NODES_FP},
        BaseBlind, FuncId, Keypair, MerkleNode, MerkleTree, PublicKey, ScalarBlind, SecretKey,
        MONEY_CONTRACT_ID,
    },
    dark_tree::DarkLeaf,
    pasta::pallas,
    ContractCall,
};
use darkfi_serial::{deserialize_async, serialize_async, AsyncEncodable};

use crate::{
    cli_util::kaching,
    convert_named_params,
    error::WalletDbResult,
    walletdb::{WalletSmt, WalletStorage},
    Drk,
};

// Wallet SQL table constant names. These have to represent the `money.sql`
// SQL schema. Table names are prefixed with the contract ID to avoid collisions.
lazy_static! {
    pub static ref MONEY_TREE_TABLE: String =
        format!("{}_money_tree", MONEY_CONTRACT_ID.to_string());
    pub static ref MONEY_SMT_TABLE: String = format!("{}_money_smt", MONEY_CONTRACT_ID.to_string());
    pub static ref MONEY_KEYS_TABLE: String =
        format!("{}_money_keys", MONEY_CONTRACT_ID.to_string());
    pub static ref MONEY_COINS_TABLE: String =
        format!("{}_money_coins", MONEY_CONTRACT_ID.to_string());
    pub static ref MONEY_TOKENS_TABLE: String =
        format!("{}_money_tokens", MONEY_CONTRACT_ID.to_string());
    pub static ref MONEY_ALIASES_TABLE: String =
        format!("{}_money_aliases", MONEY_CONTRACT_ID.to_string());
}

// MONEY_TREE_TABLE
pub const MONEY_TREE_COL_TREE: &str = "tree";

// MONEY_SMT_TABLE
pub const MONEY_SMT_COL_KEY: &str = "smt_key";
pub const MONEY_SMT_COL_VALUE: &str = "smt_value";

// MONEY_KEYS_TABLE
pub const MONEY_KEYS_COL_KEY_ID: &str = "key_id";
pub const MONEY_KEYS_COL_IS_DEFAULT: &str = "is_default";
pub const MONEY_KEYS_COL_PUBLIC: &str = "public";
pub const MONEY_KEYS_COL_SECRET: &str = "secret";

// MONEY_COINS_TABLE
pub const MONEY_COINS_COL_COIN: &str = "coin";
pub const MONEY_COINS_COL_IS_SPENT: &str = "is_spent";
pub const MONEY_COINS_COL_VALUE: &str = "value";
pub const MONEY_COINS_COL_TOKEN_ID: &str = "token_id";
pub const MONEY_COINS_COL_SPEND_HOOK: &str = "spend_hook";
pub const MONEY_COINS_COL_USER_DATA: &str = "user_data";
pub const MONEY_COINS_COL_COIN_BLIND: &str = "coin_blind";
pub const MONEY_COINS_COL_VALUE_BLIND: &str = "value_blind";
pub const MONEY_COINS_COL_TOKEN_BLIND: &str = "token_blind";
pub const MONEY_COINS_COL_SECRET: &str = "secret";
pub const MONEY_COINS_COL_LEAF_POSITION: &str = "leaf_position";
pub const MONEY_COINS_COL_MEMO: &str = "memo";
pub const MONEY_COINS_COL_SPENT_TX_HASH: &str = "spent_tx_hash";

// MONEY_TOKENS_TABLE
pub const MONEY_TOKENS_COL_TOKEN_ID: &str = "token_id";
pub const MONEY_TOKENS_COL_MINT_AUTHORITY: &str = "mint_authority";
pub const MONEY_TOKENS_COL_TOKEN_BLIND: &str = "token_blind";
pub const MONEY_TOKENS_COL_IS_FROZEN: &str = "is_frozen";

// MONEY_ALIASES_TABLE
pub const MONEY_ALIASES_COL_ALIAS: &str = "alias";
pub const MONEY_ALIASES_COL_TOKEN_ID: &str = "token_id";

pub const BALANCE_BASE10_DECIMALS: usize = 8;

impl Drk {
    /// Initialize wallet with tables for the Money contract.
    pub async fn initialize_money(&self) -> WalletDbResult<()> {
        // Initialize Money wallet schema
        let wallet_schema = include_str!("../money.sql");
        self.wallet.exec_batch_sql(wallet_schema)?;

        // Check if we have to initialize the Merkle tree.
        // We check if we find a row in the tree table, and if not, we create a
        // new tree and push it into the table.
        // For now, on success, we don't care what's returned, but in the future
        // we should actually check it.
        if self.get_money_tree().await.is_err() {
            println!("Initializing Money Merkle tree");
            let mut tree = MerkleTree::new(1);
            tree.append(MerkleNode::from(pallas::Base::ZERO));
            let _ = tree.mark().unwrap();
            let query =
                format!("INSERT INTO {} ({}) VALUES (?1);", *MONEY_TREE_TABLE, MONEY_TREE_COL_TREE);
            self.wallet.exec_sql(&query, rusqlite::params![serialize_async(&tree).await])?;
            println!("Successfully initialized Merkle tree for the Money contract");
        }

        // Insert DRK alias
        self.add_alias("DRK".to_string(), *DARK_TOKEN_ID).await?;

        Ok(())
    }

    /// Generate a new keypair and place it into the wallet.
    pub async fn money_keygen(&self) -> WalletDbResult<()> {
        println!("Generating a new keypair");

        // TODO: We might want to have hierarchical deterministic key derivation.
        let keypair = Keypair::random(&mut OsRng);
        let is_default = 0;

        let query = format!(
            "INSERT INTO {} ({}, {}, {}) VALUES (?1, ?2, ?3);",
            *MONEY_KEYS_TABLE,
            MONEY_KEYS_COL_IS_DEFAULT,
            MONEY_KEYS_COL_PUBLIC,
            MONEY_KEYS_COL_SECRET
        );
        self.wallet.exec_sql(
            &query,
            rusqlite::params![
                is_default,
                serialize_async(&keypair.public).await,
                serialize_async(&keypair.secret).await
            ],
        )?;

        println!("New address:");
        println!("{}", keypair.public);

        Ok(())
    }

    /// Fetch default secret key from the wallet.
    pub async fn default_secret(&self) -> Result<SecretKey> {
        let row = match self.wallet.query_single(
            &MONEY_KEYS_TABLE,
            &[MONEY_KEYS_COL_SECRET],
            convert_named_params! {(MONEY_KEYS_COL_IS_DEFAULT, 1)},
        ) {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::DatabaseError(format!(
                    "[default_secret] Default secret key retrieval failed: {e:?}"
                )))
            }
        };

        let Value::Blob(ref key_bytes) = row[0] else {
            return Err(Error::ParseFailed("[default_secret] Key bytes parsing failed"))
        };
        let secret_key: SecretKey = deserialize_async(key_bytes).await?;

        Ok(secret_key)
    }

    /// Fetch default pubkey from the wallet.
    pub async fn default_address(&self) -> Result<PublicKey> {
        let row = match self.wallet.query_single(
            &MONEY_KEYS_TABLE,
            &[MONEY_KEYS_COL_PUBLIC],
            convert_named_params! {(MONEY_KEYS_COL_IS_DEFAULT, 1)},
        ) {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::DatabaseError(format!(
                    "[default_address] Default address retrieval failed: {e:?}"
                )))
            }
        };

        let Value::Blob(ref key_bytes) = row[0] else {
            return Err(Error::ParseFailed("[default_address] Key bytes parsing failed"))
        };
        let public_key: PublicKey = deserialize_async(key_bytes).await?;

        Ok(public_key)
    }

    /// Set provided index address as default in the wallet.
    pub fn set_default_address(&self, idx: usize) -> WalletDbResult<()> {
        // First we update previous default record
        let is_default = 0;
        let query = format!("UPDATE {} SET {} = ?1", *MONEY_KEYS_TABLE, MONEY_KEYS_COL_IS_DEFAULT,);
        self.wallet.exec_sql(&query, rusqlite::params![is_default])?;

        // and then we set the new one
        let is_default = 1;
        let query = format!(
            "UPDATE {} SET {} = ?1 WHERE {} = ?2",
            *MONEY_KEYS_TABLE, MONEY_KEYS_COL_IS_DEFAULT, MONEY_KEYS_COL_KEY_ID,
        );
        self.wallet.exec_sql(&query, rusqlite::params![is_default, idx])
    }

    /// Fetch all pukeys from the wallet.
    pub async fn addresses(&self) -> Result<Vec<(u64, PublicKey, SecretKey, u64)>> {
        let rows = match self.wallet.query_multiple(&MONEY_KEYS_TABLE, &[], &[]) {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::DatabaseError(format!(
                    "[addresses] Addresses retrieval failed: {e:?}"
                )))
            }
        };

        let mut vec = Vec::with_capacity(rows.len());
        for row in rows {
            let Value::Integer(key_id) = row[0] else {
                return Err(Error::ParseFailed("[addresses] Key ID parsing failed"))
            };
            let Ok(key_id) = u64::try_from(key_id) else {
                return Err(Error::ParseFailed("[addresses] Key ID parsing failed"))
            };

            let Value::Integer(is_default) = row[1] else {
                return Err(Error::ParseFailed("[addresses] Is default parsing failed"))
            };
            let Ok(is_default) = u64::try_from(is_default) else {
                return Err(Error::ParseFailed("[addresses] Is default parsing failed"))
            };

            let Value::Blob(ref key_bytes) = row[2] else {
                return Err(Error::ParseFailed("[addresses] Public key bytes parsing failed"))
            };
            let public_key: PublicKey = deserialize_async(key_bytes).await?;

            let Value::Blob(ref key_bytes) = row[3] else {
                return Err(Error::ParseFailed("[addresses] Secret key bytes parsing failed"))
            };
            let secret_key: SecretKey = deserialize_async(key_bytes).await?;

            vec.push((key_id, public_key, secret_key, is_default));
        }

        Ok(vec)
    }

    /// Fetch all secret keys from the wallet.
    pub async fn get_money_secrets(&self) -> Result<Vec<SecretKey>> {
        let rows =
            match self.wallet.query_multiple(&MONEY_KEYS_TABLE, &[MONEY_KEYS_COL_SECRET], &[]) {
                Ok(r) => r,
                Err(e) => {
                    return Err(Error::DatabaseError(format!(
                        "[get_money_secrets] Secret keys retrieval failed: {e:?}"
                    )))
                }
            };

        let mut secrets = Vec::with_capacity(rows.len());

        // Let's scan through the rows and see if we got anything.
        for row in rows {
            let Value::Blob(ref key_bytes) = row[0] else {
                return Err(Error::ParseFailed(
                    "[get_money_secrets] Secret key bytes parsing failed",
                ))
            };
            let secret_key: SecretKey = deserialize_async(key_bytes).await?;
            secrets.push(secret_key);
        }

        Ok(secrets)
    }

    /// Import given secret keys into the wallet.
    /// If the key already exists, it will be skipped.
    /// Returns the respective PublicKey objects for the imported keys.
    pub async fn import_money_secrets(&self, secrets: Vec<SecretKey>) -> Result<Vec<PublicKey>> {
        let existing_secrets = self.get_money_secrets().await?;

        let mut ret = Vec::with_capacity(secrets.len());

        for secret in secrets {
            // Check if secret already exists
            if existing_secrets.contains(&secret) {
                println!("Existing key found: {secret}");
                continue
            }

            ret.push(PublicKey::from_secret(secret));
            let is_default = 0;
            let public = serialize_async(&PublicKey::from_secret(secret)).await;
            let secret = serialize_async(&secret).await;

            let query = format!(
                "INSERT INTO {} ({}, {}, {}) VALUES (?1, ?2, ?3);",
                *MONEY_KEYS_TABLE,
                MONEY_KEYS_COL_IS_DEFAULT,
                MONEY_KEYS_COL_PUBLIC,
                MONEY_KEYS_COL_SECRET
            );
            if let Err(e) =
                self.wallet.exec_sql(&query, rusqlite::params![is_default, public, secret])
            {
                return Err(Error::DatabaseError(format!(
                    "[import_money_secrets] Inserting new address failed: {e:?}"
                )))
            }
        }

        Ok(ret)
    }

    /// Fetch known unspent balances from the wallet and return them as a hashmap.
    pub async fn money_balance(&self) -> Result<HashMap<String, u64>> {
        let mut coins = self.get_coins(false).await?;
        coins.retain(|x| x.0.note.spend_hook == FuncId::none());

        // Fill this map with balances
        let mut balmap: HashMap<String, u64> = HashMap::new();

        for coin in coins {
            let mut value = coin.0.note.value;

            if let Some(prev) = balmap.get(&coin.0.note.token_id.to_string()) {
                value += prev;
            }

            balmap.insert(coin.0.note.token_id.to_string(), value);
        }

        Ok(balmap)
    }

    /// Fetch all coins and their metadata related to the Money contract from the wallet.
    /// Optionally also fetch spent ones.
    /// The boolean in the returned tuple notes if the coin was marked as spent.
    pub async fn get_coins(&self, fetch_spent: bool) -> Result<Vec<(OwnCoin, bool, String)>> {
        let query = if fetch_spent {
            self.wallet.query_multiple(&MONEY_COINS_TABLE, &[], &[])
        } else {
            self.wallet.query_multiple(
                &MONEY_COINS_TABLE,
                &[],
                convert_named_params! {(MONEY_COINS_COL_IS_SPENT, false)},
            )
        };

        let rows = match query {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::DatabaseError(format!(
                    "[get_coins] Coins retrieval failed: {e:?}"
                )))
            }
        };

        let mut owncoins = Vec::with_capacity(rows.len());
        for row in rows {
            owncoins.push(self.parse_coin_record(&row).await?)
        }

        Ok(owncoins)
    }

    /// Fetch provided transaction coins from the wallet.
    pub async fn get_transaction_coins(&self, spent_tx_hash: &String) -> Result<Vec<OwnCoin>> {
        let query = self.wallet.query_multiple(
            &MONEY_COINS_TABLE,
            &[],
            convert_named_params! {(MONEY_COINS_COL_SPENT_TX_HASH, spent_tx_hash)},
        );

        let rows = match query {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::DatabaseError(format!(
                    "[get_transaction_coins] Coins retrieval failed: {e:?}"
                )))
            }
        };

        let mut owncoins = Vec::with_capacity(rows.len());
        for row in rows {
            owncoins.push(self.parse_coin_record(&row).await?.0)
        }

        Ok(owncoins)
    }

    /// Fetch provided token unspend balances from the wallet.
    pub async fn get_token_coins(&self, token_id: &TokenId) -> Result<Vec<OwnCoin>> {
        let query = self.wallet.query_multiple(
            &MONEY_COINS_TABLE,
            &[],
            convert_named_params! {(MONEY_COINS_COL_IS_SPENT, false), (MONEY_COINS_COL_TOKEN_ID, serialize_async(token_id).await), (MONEY_COINS_COL_SPEND_HOOK, serialize_async(&FuncId::none()).await)},
        );

        let rows = match query {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::DatabaseError(format!(
                    "[get_token_coins] Coins retrieval failed: {e:?}"
                )))
            }
        };

        let mut owncoins = Vec::with_capacity(rows.len());
        for row in rows {
            owncoins.push(self.parse_coin_record(&row).await?.0)
        }

        Ok(owncoins)
    }

    /// Fetch provided contract specified token unspend balances from the wallet.
    pub async fn get_contract_token_coins(
        &self,
        token_id: &TokenId,
        spend_hook: &FuncId,
        user_data: &pallas::Base,
    ) -> Result<Vec<OwnCoin>> {
        let query = self.wallet.query_multiple(
            &MONEY_COINS_TABLE,
            &[],
            convert_named_params! {(MONEY_COINS_COL_IS_SPENT, false), (MONEY_COINS_COL_TOKEN_ID, serialize_async(token_id).await), (MONEY_COINS_COL_SPEND_HOOK, serialize_async(spend_hook).await), (MONEY_COINS_COL_USER_DATA, serialize_async(user_data).await)},
        );

        let rows = match query {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::DatabaseError(format!(
                    "[get_contract_token_coins] Coins retrieval failed: {e:?}"
                )))
            }
        };

        let mut owncoins = Vec::with_capacity(rows.len());
        for row in rows {
            owncoins.push(self.parse_coin_record(&row).await?.0)
        }

        Ok(owncoins)
    }

    /// Auxiliary function to parse a `MONEY_COINS_TABLE` record.
    /// The boolean in the returned tuple notes if the coin was marked as spent.
    async fn parse_coin_record(&self, row: &[Value]) -> Result<(OwnCoin, bool, String)> {
        let Value::Blob(ref coin_bytes) = row[0] else {
            return Err(Error::ParseFailed("[parse_coin_record] Coin bytes parsing failed"))
        };
        let coin: Coin = deserialize_async(coin_bytes).await?;

        let Value::Integer(is_spent) = row[1] else {
            return Err(Error::ParseFailed("[parse_coin_record] Is spent parsing failed"))
        };
        let Ok(is_spent) = u64::try_from(is_spent) else {
            return Err(Error::ParseFailed("[parse_coin_record] Is spent parsing failed"))
        };
        let is_spent = is_spent > 0;

        let Value::Blob(ref value_bytes) = row[2] else {
            return Err(Error::ParseFailed("[parse_coin_record] Value bytes parsing failed"))
        };
        let value: u64 = deserialize_async(value_bytes).await?;

        let Value::Blob(ref token_id_bytes) = row[3] else {
            return Err(Error::ParseFailed("[parse_coin_record] Token ID bytes parsing failed"))
        };
        let token_id: TokenId = deserialize_async(token_id_bytes).await?;

        let Value::Blob(ref spend_hook_bytes) = row[4] else {
            return Err(Error::ParseFailed("[parse_coin_record] Spend hook bytes parsing failed"))
        };
        let spend_hook: pallas::Base = deserialize_async(spend_hook_bytes).await?;

        let Value::Blob(ref user_data_bytes) = row[5] else {
            return Err(Error::ParseFailed("[parse_coin_record] User data bytes parsing failed"))
        };
        let user_data: pallas::Base = deserialize_async(user_data_bytes).await?;

        let Value::Blob(ref coin_blind_bytes) = row[6] else {
            return Err(Error::ParseFailed("[parse_coin_record] Coin blind bytes parsing failed"))
        };
        let coin_blind: BaseBlind = deserialize_async(coin_blind_bytes).await?;

        let Value::Blob(ref value_blind_bytes) = row[7] else {
            return Err(Error::ParseFailed("[parse_coin_record] Value blind bytes parsing failed"))
        };
        let value_blind: ScalarBlind = deserialize_async(value_blind_bytes).await?;

        let Value::Blob(ref token_blind_bytes) = row[8] else {
            return Err(Error::ParseFailed("[parse_coin_record] Token blind bytes parsing failed"))
        };
        let token_blind: BaseBlind = deserialize_async(token_blind_bytes).await?;

        let Value::Blob(ref secret_bytes) = row[9] else {
            return Err(Error::ParseFailed("[parse_coin_record] Secret bytes parsing failed"))
        };
        let secret: SecretKey = deserialize_async(secret_bytes).await?;

        let Value::Blob(ref leaf_position_bytes) = row[10] else {
            return Err(Error::ParseFailed("[parse_coin_record] Leaf position bytes parsing failed"))
        };
        let leaf_position: bridgetree::Position = deserialize_async(leaf_position_bytes).await?;

        let Value::Blob(ref memo) = row[11] else {
            return Err(Error::ParseFailed("[parse_coin_record] Memo parsing failed"))
        };

        let Value::Text(ref spent_tx_hash) = row[12] else {
            return Err(Error::ParseFailed(
                "[parse_coin_record] Spent transaction hash parsing failed",
            ))
        };

        let note = MoneyNote {
            value,
            token_id,
            spend_hook: spend_hook.into(),
            user_data,
            coin_blind,
            value_blind,
            token_blind,
            memo: memo.clone(),
        };

        Ok((OwnCoin { coin, note, secret, leaf_position }, is_spent, spent_tx_hash.clone()))
    }

    /// Create an alias record for provided Token ID.
    pub async fn add_alias(&self, alias: String, token_id: TokenId) -> WalletDbResult<()> {
        println!("Generating alias {alias} for Token: {token_id}");
        let query = format!(
            "INSERT OR REPLACE INTO {} ({}, {}) VALUES (?1, ?2);",
            *MONEY_ALIASES_TABLE, MONEY_ALIASES_COL_ALIAS, MONEY_ALIASES_COL_TOKEN_ID,
        );
        self.wallet.exec_sql(
            &query,
            rusqlite::params![serialize_async(&alias).await, serialize_async(&token_id).await],
        )
    }

    /// Fetch all aliases from the wallet.
    /// Optionally filter using alias name and/or token id.
    pub async fn get_aliases(
        &self,
        alias_filter: Option<String>,
        token_id_filter: Option<TokenId>,
    ) -> Result<HashMap<String, TokenId>> {
        let rows = match self.wallet.query_multiple(&MONEY_ALIASES_TABLE, &[], &[]) {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::DatabaseError(format!(
                    "[get_aliases] Aliases retrieval failed: {e:?}"
                )))
            }
        };

        // Fill this map with aliases
        let mut map: HashMap<String, TokenId> = HashMap::new();
        for row in rows {
            let Value::Blob(ref alias_bytes) = row[0] else {
                return Err(Error::ParseFailed("[get_aliases] Alias bytes parsing failed"))
            };
            let alias: String = deserialize_async(alias_bytes).await?;
            if alias_filter.is_some() && alias_filter.as_ref().unwrap() != &alias {
                continue
            }

            let Value::Blob(ref token_id_bytes) = row[1] else {
                return Err(Error::ParseFailed("[get_aliases] TokenId bytes parsing failed"))
            };
            let token_id: TokenId = deserialize_async(token_id_bytes).await?;
            if token_id_filter.is_some() && token_id_filter.as_ref().unwrap() != &token_id {
                continue
            }

            map.insert(alias, token_id);
        }

        Ok(map)
    }

    /// Fetch all aliases from the wallet, mapped by token id.
    pub async fn get_aliases_mapped_by_token(&self) -> Result<HashMap<String, String>> {
        let aliases = self.get_aliases(None, None).await?;
        let mut map: HashMap<String, String> = HashMap::new();
        for (alias, token_id) in aliases {
            let aliases_string = if let Some(prev) = map.get(&token_id.to_string()) {
                format!("{prev}, {alias}")
            } else {
                alias
            };

            map.insert(token_id.to_string(), aliases_string);
        }

        Ok(map)
    }

    /// Remove provided alias record from the wallet database.
    pub async fn remove_alias(&self, alias: String) -> WalletDbResult<()> {
        println!("Removing alias: {alias}");
        let query = format!(
            "DELETE FROM {} WHERE {} = ?1;",
            *MONEY_ALIASES_TABLE, MONEY_ALIASES_COL_ALIAS,
        );
        self.wallet.exec_sql(&query, rusqlite::params![serialize_async(&alias).await])
    }

    /// Mark a given coin in the wallet as unspent.
    pub async fn unspend_coin(&self, coin: &Coin) -> WalletDbResult<()> {
        let is_spend = 0;
        let query = format!(
            "UPDATE {} SET {} = ?1, {} = ?2 WHERE {} = ?3;",
            *MONEY_COINS_TABLE,
            MONEY_COINS_COL_IS_SPENT,
            MONEY_COINS_COL_SPENT_TX_HASH,
            MONEY_COINS_COL_COIN
        );
        self.wallet.exec_sql(
            &query,
            rusqlite::params![is_spend, "-", serialize_async(&coin.inner()).await],
        )
    }

    /// Replace the Money Merkle tree in the wallet.
    pub async fn put_money_tree(&self, tree: &MerkleTree) -> WalletDbResult<()> {
        let query = format!("UPDATE {} SET {} = ?1;", *MONEY_TREE_TABLE, MONEY_TREE_COL_TREE);
        self.wallet.exec_sql(&query, rusqlite::params![serialize_async(tree).await])
    }

    /// Fetch the Money Merkle tree from the wallet.
    pub async fn get_money_tree(&self) -> Result<MerkleTree> {
        let row = match self.wallet.query_single(&MONEY_TREE_TABLE, &[MONEY_TREE_COL_TREE], &[]) {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::DatabaseError(format!(
                    "[get_money_tree] Tree retrieval failed: {e:?}"
                )))
            }
        };

        let Value::Blob(ref tree_bytes) = row[0] else {
            return Err(Error::ParseFailed("[get_money_tree] Tree bytes parsing failed"))
        };
        let tree = deserialize_async(tree_bytes).await?;
        Ok(tree)
    }

    /// Auxiliary function to fetch the current Money Merkle tree state,
    /// as an update query.
    pub async fn get_money_tree_state_query(&self) -> Result<String> {
        // Grab current money tree
        let tree = self.get_money_tree().await?;

        // Create the update query
        match self.wallet.create_prepared_statement(
            &format!("UPDATE {} SET {} = ?1;", *MONEY_TREE_TABLE, MONEY_TREE_COL_TREE),
            rusqlite::params![serialize_async(&tree).await],
        ) {
            Ok(q) => Ok(q),
            Err(e) => Err(Error::DatabaseError(format!(
                "[get_money_tree_state_query] Creating query for money tree failed: {e:?}"
            ))),
        }
    }

    /// Fetch the Money nullifiers SMT from the wallet, as a map.
    pub async fn get_nullifiers_smt(&self) -> Result<HashMap<BigUint, pallas::Base>> {
        let rows = match self.wallet.query_multiple(&MONEY_SMT_TABLE, &[], &[]) {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::DatabaseError(format!(
                    "[get_nullifiers_smt] SMT records retrieval failed: {e:?}"
                )))
            }
        };

        let mut smt = HashMap::new();
        for row in rows {
            let Value::Blob(ref key_bytes) = row[0] else {
                return Err(Error::ParseFailed("[get_nullifiers_smt] Key bytes parsing failed"))
            };
            let key = BigUint::from_bytes_le(key_bytes);

            let Value::Blob(ref value_bytes) = row[1] else {
                return Err(Error::ParseFailed("[get_nullifiers_smt] Value bytes parsing failed"))
            };
            let mut repr = [0; 32];
            repr.copy_from_slice(value_bytes);
            let Some(value) = pallas::Base::from_repr(repr).into() else {
                return Err(Error::ParseFailed("[get_nullifiers_smt] Value conversion failed"))
            };

            smt.insert(key, value);
        }

        Ok(smt)
    }

    /// Auxiliary function to grab all the nullifiers, coins, notes and freezes from
    /// a transaction money call.
    async fn parse_money_call(
        &self,
        call_idx: usize,
        calls: &[DarkLeaf<ContractCall>],
    ) -> Result<(Vec<Nullifier>, Vec<Coin>, Vec<AeadEncryptedNote>, Vec<TokenId>)> {
        let mut nullifiers: Vec<Nullifier> = vec![];
        let mut coins: Vec<Coin> = vec![];
        let mut notes: Vec<AeadEncryptedNote> = vec![];
        let mut freezes: Vec<TokenId> = vec![];

        let call = &calls[call_idx];
        let data = &call.data.data;
        match MoneyFunction::try_from(data[0])? {
            MoneyFunction::FeeV1 => {
                println!("[parse_money_call] Found Money::FeeV1 call");
                let params: MoneyFeeParamsV1 = deserialize_async(&data[9..]).await?;
                nullifiers.push(params.input.nullifier);
                coins.push(params.output.coin);
                notes.push(params.output.note);
            }
            MoneyFunction::GenesisMintV1 => {
                println!("[parse_money_call] Found Money::GenesisMintV1 call");
                let params: MoneyGenesisMintParamsV1 = deserialize_async(&data[1..]).await?;
                for output in params.outputs {
                    coins.push(output.coin);
                    notes.push(output.note);
                }
            }
            MoneyFunction::PoWRewardV1 => {
                println!("[parse_money_call] Found Money::PoWRewardV1 call");
                let params: MoneyPoWRewardParamsV1 = deserialize_async(&data[1..]).await?;
                coins.push(params.output.coin);
                notes.push(params.output.note);
            }
            MoneyFunction::TransferV1 => {
                println!("[parse_money_call] Found Money::TransferV1 call");
                let params: MoneyTransferParamsV1 = deserialize_async(&data[1..]).await?;

                for input in params.inputs {
                    nullifiers.push(input.nullifier);
                }

                for output in params.outputs {
                    coins.push(output.coin);
                    notes.push(output.note);
                }
            }
            MoneyFunction::OtcSwapV1 => {
                println!("[parse_money_call] Found Money::OtcSwapV1 call");
                let params: MoneyTransferParamsV1 = deserialize_async(&data[1..]).await?;

                for input in params.inputs {
                    nullifiers.push(input.nullifier);
                }

                for output in params.outputs {
                    coins.push(output.coin);
                    notes.push(output.note);
                }
            }
            MoneyFunction::AuthTokenMintV1 => {
                println!("[parse_money_call] Found Money::AuthTokenMintV1 call");
                // Handled in TokenMint
            }
            MoneyFunction::AuthTokenFreezeV1 => {
                println!("[parse_money_call] Found Money::AuthTokenFreezeV1 call");
                let params: MoneyAuthTokenFreezeParamsV1 = deserialize_async(&data[1..]).await?;
                freezes.push(params.token_id);
            }
            MoneyFunction::TokenMintV1 => {
                println!("[parse_money_call] Found Money::TokenMintV1 call");
                let params: MoneyTokenMintParamsV1 = deserialize_async(&data[1..]).await?;
                coins.push(params.coin);
                // Grab the note from the child auth call
                let child_idx = call.children_indexes[0];
                let child_call = &calls[child_idx];
                let params: MoneyAuthTokenMintParamsV1 =
                    deserialize_async(&child_call.data.data[1..]).await?;
                notes.push(params.enc_note);
            }
        }

        Ok((nullifiers, coins, notes, freezes))
    }

    /// Append data related to Money contract transactions into the wallet database,
    /// and store their inverse queries into the cache.
    /// Returns a flag indicating if the provided data refer to our own wallet.
    pub async fn apply_tx_money_data(
        &self,
        call_idx: usize,
        calls: &[DarkLeaf<ContractCall>],
        tx_hash: &String,
    ) -> Result<bool> {
        let (nullifiers, coins, notes, freezes) = self.parse_money_call(call_idx, calls).await?;
        let secrets = self.get_money_secrets().await?;
        let dao_notes_secrets = self.get_dao_notes_secrets().await?;
        let mut tree = self.get_money_tree().await?;

        let mut owncoins = vec![];

        for (coin, note) in coins.iter().zip(notes.iter()) {
            // Append the new coin to the Merkle tree. Every coin has to be added.
            tree.append(MerkleNode::from(coin.inner()));

            // Attempt to decrypt the note
            for secret in secrets.iter().chain(dao_notes_secrets.iter()) {
                if let Ok(note) = note.decrypt::<MoneyNote>(secret) {
                    println!("[apply_tx_money_data] Successfully decrypted a Money Note");
                    println!("[apply_tx_money_data] Witnessing coin in Merkle tree");
                    let leaf_position = tree.mark().unwrap();

                    let owncoin =
                        OwnCoin { coin: *coin, note: note.clone(), secret: *secret, leaf_position };

                    owncoins.push(owncoin);
                }
            }
        }

        if let Err(e) = self.put_money_tree(&tree).await {
            return Err(Error::DatabaseError(format!(
                "[apply_tx_money_data] Put Money tree failed: {e:?}"
            )))
        }
        self.smt_insert(&nullifiers)?;
        let wallet_spent_coins = self.mark_spent_coins(&nullifiers, tx_hash).await?;

        // This is the SQL query we'll be executing to insert new coins into the wallet
        let query = format!(
            "INSERT INTO {} ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12);",
            *MONEY_COINS_TABLE,
            MONEY_COINS_COL_COIN,
            MONEY_COINS_COL_IS_SPENT,
            MONEY_COINS_COL_VALUE,
            MONEY_COINS_COL_TOKEN_ID,
            MONEY_COINS_COL_SPEND_HOOK,
            MONEY_COINS_COL_USER_DATA,
            MONEY_COINS_COL_COIN_BLIND,
            MONEY_COINS_COL_VALUE_BLIND,
            MONEY_COINS_COL_TOKEN_BLIND,
            MONEY_COINS_COL_SECRET,
            MONEY_COINS_COL_LEAF_POSITION,
            MONEY_COINS_COL_MEMO,
        );

        // This is its inverse query
        let inverse_query =
            format!("DELETE FROM {} WHERE {} = ?1;", *MONEY_COINS_TABLE, MONEY_COINS_COL_COIN);

        println!("Found {} OwnCoin(s) in transaction", owncoins.len());
        for owncoin in &owncoins {
            println!("OwnCoin: {:?}", owncoin.coin);
            // Grab coin record key
            let key = serialize_async(&owncoin.coin).await;

            // Create its inverse query
            let inverse =
                match self.wallet.create_prepared_statement(&inverse_query, rusqlite::params![key])
                {
                    Ok(q) => q,
                    Err(e) => {
                        return Err(Error::DatabaseError(format!(
                    "[apply_tx_money_data] Creating Money coin insert inverse query failed: {e:?}"
                )))
                    }
                };

            // Execute the query
            let params = rusqlite::params![
                key,
                0, // <-- is_spent
                serialize_async(&owncoin.note.value).await,
                serialize_async(&owncoin.note.token_id).await,
                serialize_async(&owncoin.note.spend_hook).await,
                serialize_async(&owncoin.note.user_data).await,
                serialize_async(&owncoin.note.coin_blind).await,
                serialize_async(&owncoin.note.value_blind).await,
                serialize_async(&owncoin.note.token_blind).await,
                serialize_async(&owncoin.secret).await,
                serialize_async(&owncoin.leaf_position).await,
                serialize_async(&owncoin.note.memo).await,
            ];

            if let Err(e) = self.wallet.exec_sql(&query, params) {
                return Err(Error::DatabaseError(format!(
                    "[apply_tx_money_data] Inserting Money coin failed: {e:?}"
                )))
            }

            // Store its inverse
            if let Err(e) = self.wallet.cache_inverse(inverse) {
                return Err(Error::DatabaseError(format!(
                    "[apply_tx_money_data] Inserting inverse query into cache failed: {e:?}"
                )))
            }
        }

        // This is the SQL query we'll be executing to update frozen tokens into the wallet
        let query = format!(
            "UPDATE {} SET {} = 1 WHERE {} = ?1;",
            *MONEY_TOKENS_TABLE, MONEY_TOKENS_COL_IS_FROZEN, MONEY_TOKENS_COL_TOKEN_ID,
        );

        // This is its inverse query
        let inverse_query = format!(
            "UPDATE {} SET {} = 0 WHERE {} = ?1;",
            *MONEY_TOKENS_TABLE, MONEY_TOKENS_COL_IS_FROZEN, MONEY_TOKENS_COL_TOKEN_ID,
        );

        for token_id in &freezes {
            // Grab token record key
            let key = serialize_async(token_id).await;

            // Create its inverse query
            let inverse =
                match self.wallet.create_prepared_statement(&inverse_query, rusqlite::params![key])
                {
                    Ok(q) => q,
                    Err(e) => {
                        return Err(Error::DatabaseError(format!(
                    "[apply_tx_money_data] Creating Money token freeze inverse query failed: {e:?}"
                )))
                    }
                };

            // Execute the query
            if let Err(e) = self.wallet.exec_sql(&query, rusqlite::params![key]) {
                return Err(Error::DatabaseError(format!(
                    "[apply_tx_money_data] Update Money token freeze failed: {e:?}"
                )))
            }

            // Store its inverse
            if let Err(e) = self.wallet.cache_inverse(inverse) {
                return Err(Error::DatabaseError(format!(
                    "[apply_tx_money_data] Inserting inverse query into cache failed: {e:?}"
                )))
            }
        }

        if self.fun && !owncoins.is_empty() {
            kaching().await;
        }

        Ok(wallet_spent_coins || !owncoins.is_empty() || !freezes.is_empty())
    }

    /// Auxiliary function to  grab all the nullifiers from a transaction money call.
    async fn money_call_nullifiers(&self, call: &DarkLeaf<ContractCall>) -> Result<Vec<Nullifier>> {
        let mut nullifiers: Vec<Nullifier> = vec![];

        let data = &call.data.data;
        match MoneyFunction::try_from(data[0])? {
            MoneyFunction::FeeV1 => {
                let params: MoneyFeeParamsV1 = deserialize_async(&data[9..]).await?;
                nullifiers.push(params.input.nullifier);
            }
            MoneyFunction::TransferV1 => {
                let params: MoneyTransferParamsV1 = deserialize_async(&data[1..]).await?;

                for input in params.inputs {
                    nullifiers.push(input.nullifier);
                }
            }
            MoneyFunction::OtcSwapV1 => {
                let params: MoneyTransferParamsV1 = deserialize_async(&data[1..]).await?;

                for input in params.inputs {
                    nullifiers.push(input.nullifier);
                }
            }
            _ => { /* Do nothing */ }
        }

        Ok(nullifiers)
    }

    /// Mark provided transaction input coins as spent.
    pub async fn mark_tx_spend(&self, tx: &Transaction) -> Result<()> {
        let tx_hash = tx.hash().to_string();
        println!("[mark_tx_spend] Processing transaction: {tx_hash}");
        for (i, call) in tx.calls.iter().enumerate() {
            if call.data.contract_id != *MONEY_CONTRACT_ID {
                continue
            }

            println!("[mark_tx_spend] Found Money contract in call {i}");
            let nullifiers = self.money_call_nullifiers(call).await?;
            self.mark_spent_coins(&nullifiers, &tx_hash).await?;
        }

        Ok(())
    }

    /// Mark a coin in the wallet as spent, and store its inverse query into the cache.
    pub async fn mark_spent_coin(&self, coin: &Coin, spent_tx_hash: &String) -> WalletDbResult<()> {
        // Grab coin record key
        let key = serialize_async(&coin.inner()).await;

        // Create an SQL `UPDATE` query to mark rows as spent(1)
        let query = format!(
            "UPDATE {} SET {} = 1, {} = ?1 WHERE {} = ?2;",
            *MONEY_COINS_TABLE,
            MONEY_COINS_COL_IS_SPENT,
            MONEY_COINS_COL_SPENT_TX_HASH,
            MONEY_COINS_COL_COIN
        );

        // Create its inverse query
        let inverse = self.wallet.create_prepared_statement(
            &format!(
                "UPDATE {} SET {} = 0, {} = '-' WHERE {} = ?1;",
                *MONEY_COINS_TABLE,
                MONEY_COINS_COL_IS_SPENT,
                MONEY_COINS_COL_SPENT_TX_HASH,
                MONEY_COINS_COL_COIN
            ),
            rusqlite::params![key],
        )?;

        // Execute the query
        self.wallet.exec_sql(&query, rusqlite::params![spent_tx_hash, key])?;

        // Store its inverse
        self.wallet.cache_inverse(inverse)
    }

    /// Marks all coins in the wallet as spent, if their nullifier is in the given set.
    /// Returns a flag indicating if any of the provided nullifiers refer to our own wallet.
    pub async fn mark_spent_coins(
        &self,
        nullifiers: &[Nullifier],
        spent_tx_hash: &String,
    ) -> Result<bool> {
        if nullifiers.is_empty() {
            return Ok(false)
        }

        // First we remark transaction spent coins
        let mut wallet_spent_coins = false;
        for coin in self.get_transaction_coins(spent_tx_hash).await? {
            if let Err(e) = self.mark_spent_coin(&coin.coin, spent_tx_hash).await {
                return Err(Error::DatabaseError(format!(
                    "[mark_spent_coins] Marking spent coin failed: {e:?}"
                )))
            }
            wallet_spent_coins = true;
        }

        // Then we mark transaction unspent coins
        for (coin, _, _) in self.get_coins(false).await? {
            if !nullifiers.contains(&coin.nullifier()) {
                continue
            }
            if let Err(e) = self.mark_spent_coin(&coin.coin, spent_tx_hash).await {
                return Err(Error::DatabaseError(format!(
                    "[mark_spent_coins] Marking spent coin failed: {e:?}"
                )))
            }
            wallet_spent_coins = true;
        }

        Ok(wallet_spent_coins)
    }

    /// Inserts given slice to the wallets nullifiers Sparse Merkle Tree.
    pub fn smt_insert(&self, nullifiers: &[Nullifier]) -> Result<()> {
        let store = WalletStorage::new(
            &self.wallet,
            &MONEY_SMT_TABLE,
            MONEY_SMT_COL_KEY,
            MONEY_SMT_COL_VALUE,
        );
        let mut smt = WalletSmt::new(store, PoseidonFp::new(), &EMPTY_NODES_FP);

        let leaves: Vec<_> = nullifiers.iter().map(|x| (x.inner(), x.inner())).collect();
        smt.insert_batch(leaves)?;

        Ok(())
    }

    /// Reset the Money Merkle tree in the wallet.
    pub async fn reset_money_tree(&self) -> WalletDbResult<()> {
        println!("Resetting Money Merkle tree");
        let mut tree = MerkleTree::new(1);
        tree.append(MerkleNode::from(pallas::Base::ZERO));
        let _ = tree.mark().unwrap();
        self.put_money_tree(&tree).await?;
        println!("Successfully reset Money Merkle tree");

        Ok(())
    }

    /// Reset the Money nullifiers Sparse Merkle Tree in the wallet.
    pub fn reset_money_smt(&self) -> WalletDbResult<()> {
        println!("Resetting Money Sparse Merkle tree");
        let query = format!("DELETE FROM {};", *MONEY_SMT_TABLE);
        self.wallet.exec_sql(&query, &[])?;
        println!("Successfully reset Money Sparse Merkle tree");

        Ok(())
    }

    /// Reset the Money coins in the wallet.
    pub fn reset_money_coins(&self) -> WalletDbResult<()> {
        println!("Resetting coins");
        let query = format!("DELETE FROM {};", *MONEY_COINS_TABLE);
        self.wallet.exec_sql(&query, &[])?;
        println!("Successfully reset coins");

        Ok(())
    }

    /// Retrieve token by provided string.
    /// Input string represents either an alias or a token id.
    pub async fn get_token(&self, input: String) -> Result<TokenId> {
        // Check if input is an alias(max 5 characters)
        if input.chars().count() <= 5 {
            let aliases = self.get_aliases(Some(input.clone()), None).await?;
            if let Some(token_id) = aliases.get(&input) {
                return Ok(*token_id)
            }
        }
        // Else parse input
        Ok(TokenId::from_str(input.as_str())?)
    }

    /// Create and append a `Money::Fee` call to a given [`Transaction`].
    ///
    /// Optionally takes a set of spent coins in order not to reuse them here.
    ///
    /// Returns the `Fee` call, and all necessary data and parameters related.
    pub async fn append_fee_call(
        &self,
        tx: &Transaction,
        money_merkle_tree: &MerkleTree,
        fee_pk: &ProvingKey,
        fee_zkbin: &ZkBinary,
        spent_coins: Option<&[OwnCoin]>,
    ) -> Result<(ContractCall, Vec<Proof>, Vec<SecretKey>)> {
        // First we verify the fee-less transaction to see how much fee it requires for execution
        // and verification.
        let required_fee = compute_fee(&FEE_CALL_GAS) + self.get_tx_fee(tx, false).await?;

        // Knowing the total gas, we can now find an OwnCoin of enough value
        // so that we can create a valid Money::Fee call.
        let mut available_coins = self.get_token_coins(&DARK_TOKEN_ID).await?;
        available_coins.retain(|x| x.note.value > required_fee);
        if let Some(spent_coins) = spent_coins {
            available_coins.retain(|x| !spent_coins.contains(x));
        }
        if available_coins.is_empty() {
            return Err(Error::Custom("Not enough native tokens to pay for fees".to_string()))
        }

        let coin = &available_coins[0];
        let change_value = coin.note.value - required_fee;

        // Input and output setup
        let input = FeeCallInput {
            coin: coin.clone(),
            merkle_path: money_merkle_tree.witness(coin.leaf_position, 0).unwrap(),
            user_data_blind: BaseBlind::random(&mut OsRng),
        };

        let output = FeeCallOutput {
            public_key: PublicKey::from_secret(coin.secret),
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

        // Create the actual fee proof
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
            },
            output: Output {
                value_commit: public_inputs.output_value_commit,
                token_commit: public_inputs.token_commit,
                coin: public_inputs.output_coin,
                note: encrypted_note,
            },
            fee_value_blind,
            token_blind,
        };

        // Encode the contract call
        let mut data = vec![MoneyFunction::FeeV1 as u8];
        required_fee.encode_async(&mut data).await?;
        params.encode_async(&mut data).await?;
        let call = ContractCall { contract_id: *MONEY_CONTRACT_ID, data };

        Ok((call, vec![proof], vec![signature_secret]))
    }

    /// Create and attach the fee call to given transaction.
    pub async fn attach_fee(&self, tx: &mut Transaction) -> Result<()> {
        // Grab spent coins nullifiers of the transactions and check no other fee call exists
        let mut tx_nullifiers = vec![];
        for call in &tx.calls {
            if call.data.contract_id != *MONEY_CONTRACT_ID {
                continue
            }

            match MoneyFunction::try_from(call.data.data[0])? {
                MoneyFunction::FeeV1 => {
                    return Err(Error::Custom("Fee call already exists".to_string()))
                }
                _ => { /* Do nothing */ }
            }

            let nullifiers = self.money_call_nullifiers(call).await?;
            tx_nullifiers.extend_from_slice(&nullifiers);
        }

        // Grab all native owncoins to check if any is spent
        let mut spent_coins = vec![];
        let available_coins = self.get_token_coins(&DARK_TOKEN_ID).await?;
        for coin in available_coins {
            if tx_nullifiers.contains(&coin.nullifier()) {
                spent_coins.push(coin);
            }
        }

        // Now we need to do a lookup for the zkas proof bincodes, and create
        // the circuit objects and proving keys so we can build the transaction.
        // We also do this through the RPC.
        let zkas_bins = self.lookup_zkas(&MONEY_CONTRACT_ID).await?;

        let Some(fee_zkbin) = zkas_bins.iter().find(|x| x.0 == MONEY_CONTRACT_ZKAS_FEE_NS_V1)
        else {
            return Err(Error::Custom("Fee circuit not found".to_string()))
        };

        let fee_zkbin = ZkBinary::decode(&fee_zkbin.1)?;

        let fee_circuit = ZkCircuit::new(empty_witnesses(&fee_zkbin)?, &fee_zkbin);

        // Creating Fee circuits proving keys
        let fee_pk = ProvingKey::build(fee_zkbin.k, &fee_circuit);

        // We first have to execute the fee-less tx to gather its used gas, and then we feed
        // it into the fee-creating function.
        let tree = self.get_money_tree().await?;
        let (fee_call, fee_proofs, fee_secrets) =
            self.append_fee_call(tx, &tree, &fee_pk, &fee_zkbin, Some(&spent_coins)).await?;

        // Append the fee call to the transaction
        tx.calls.push(DarkLeaf { data: fee_call, parent_index: None, children_indexes: vec![] });
        tx.proofs.push(fee_proofs);
        let sigs = tx.create_sigs(&fee_secrets)?;
        tx.signatures.push(sigs);

        Ok(())
    }
}
