/* This file is part of DarkFi (https://dark.fi)
 *
 * Copyright (C) 2020-2024 Dyne.org foundation
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

use std::collections::{HashMap, HashSet};

use darkfi_sdk::{crypto::MerkleTree, tx::TransactionHash};
use darkfi_serial::{async_trait, SerialDecodable, SerialEncodable};
use log::{debug, info, warn};
use num_bigint::BigUint;
use sled_overlay::database::SledDbOverlayStateDiff;
use smol::lock::RwLock;

use crate::{
    blockchain::{
        block_store::{BlockDifficulty, BlockRanks},
        BlockInfo, Blockchain, BlockchainOverlay, BlockchainOverlayPtr, HeaderHash,
    },
    tx::Transaction,
    validator::{
        pow::PoWModule,
        utils::{best_fork_index, block_rank, find_extended_fork_index},
        verification::{verify_proposal, verify_transaction},
    },
    zk::VerifyingKey,
    Error, Result,
};

// Consensus configuration
/// Average amount of gas consumed during transaction execution, derived by the Gas Analyzer
const GAS_TX_AVG: u64 = 23_822_290;

/// Multiplier used to calculate the gas limit for unproposed transactions
const GAS_LIMIT_MULTIPLIER_UNPROPOSED_TXS: u64 = 50;

/// Gas limit for unproposed transactions
pub const GAS_LIMIT_UNPROPOSED_TXS: u64 = GAS_TX_AVG * GAS_LIMIT_MULTIPLIER_UNPROPOSED_TXS;

/// This struct represents the information required by the consensus algorithm
pub struct Consensus {
    /// Canonical (finalized) blockchain
    pub blockchain: Blockchain,
    /// Fork size(length) after which it can be finalized
    pub finalization_threshold: usize,
    /// Fork chains containing block proposals
    pub forks: RwLock<Vec<Fork>>,
    /// Canonical blockchain PoW module state
    pub module: RwLock<PoWModule>,
    /// Lock to restrict when proposals appends can happen
    pub append_lock: RwLock<()>,
}

impl Consensus {
    /// Generate a new Consensus state.
    pub fn new(
        blockchain: Blockchain,
        finalization_threshold: usize,
        pow_target: u32,
        pow_fixed_difficulty: Option<BigUint>,
    ) -> Result<Self> {
        let forks = RwLock::new(vec![]);
        let module =
            RwLock::new(PoWModule::new(blockchain.clone(), pow_target, pow_fixed_difficulty)?);
        let append_lock = RwLock::new(());
        Ok(Self { blockchain, finalization_threshold, forks, module, append_lock })
    }

    /// Generate a new empty fork.
    pub async fn generate_empty_fork(&self) -> Result<()> {
        debug!(target: "validator::consensus::generate_empty_fork", "Generating new empty fork...");
        let mut forks = self.forks.write().await;
        // Check if we already have an empty fork
        for fork in forks.iter() {
            if fork.proposals.is_empty() {
                debug!(target: "validator::consensus::generate_empty_fork", "An empty fork already exists.");
                drop(forks);
                return Ok(())
            }
        }
        let fork = Fork::new(self.blockchain.clone(), self.module.read().await.clone()).await?;
        forks.push(fork);
        drop(forks);
        debug!(target: "validator::consensus::generate_empty_fork", "Fork generated!");
        Ok(())
    }

    /// Given a proposal, the node verifys it and finds which fork it extends.
    /// If the proposal extends the canonical blockchain, a new fork chain is created.
    pub async fn append_proposal(&self, proposal: &Proposal, verify_fees: bool) -> Result<()> {
        debug!(target: "validator::consensus::append_proposal", "Appending proposal {}", proposal.hash);

        // Check if proposal already exists
        let lock = self.forks.read().await;
        for fork in lock.iter() {
            for p in fork.proposals.iter().rev() {
                if p == &proposal.hash {
                    drop(lock);
                    debug!(target: "validator::consensus::append_proposal", "Proposal {} already exists", proposal.hash);
                    return Err(Error::ProposalAlreadyExists)
                }
            }
        }
        drop(lock);

        // Verify proposal and grab corresponding fork
        let (mut fork, index) = verify_proposal(self, proposal, verify_fees).await?;

        // Append proposal to the fork
        fork.append_proposal(proposal).await?;

        // TODO: to keep memory usage low, we should only append forks that
        // are higher ranking than our current best one

        // If a fork index was found, replace forks with the mutated one,
        // otherwise push the new fork.
        let mut lock = self.forks.write().await;
        match index {
            Some(i) => {
                if i < lock.len() && lock[i].proposals == fork.proposals[..fork.proposals.len() - 1]
                {
                    lock[i] = fork;
                } else {
                    lock.push(fork);
                }
            }
            None => {
                lock.push(fork);
            }
        }
        drop(lock);

        info!(target: "validator::consensus::append_proposal", "Appended proposal {}", proposal.hash);

        Ok(())
    }

    /// Given a proposal, find the fork chain it extends, and return its full clone.
    /// If the proposal extends the fork not on its tail, a new fork is created and
    /// we re-apply the proposals up to the extending one. If proposal extends canonical,
    /// a new fork is created. Additionally, we return the fork index if a new fork
    /// was not created, so caller can replace the fork.
    pub async fn find_extended_fork(&self, proposal: &Proposal) -> Result<(Fork, Option<usize>)> {
        // Grab a lock over current forks
        let forks = self.forks.read().await;

        // Check if proposal extends any fork
        let found = find_extended_fork_index(&forks, proposal);
        if found.is_err() {
            if let Err(Error::ProposalAlreadyExists) = found {
                return Err(Error::ProposalAlreadyExists)
            }

            // Check if proposal extends canonical
            let (last_height, last_block) = self.blockchain.last()?;
            if proposal.block.header.previous != last_block ||
                proposal.block.header.height <= last_height
            {
                return Err(Error::ExtendedChainIndexNotFound)
            }

            // Check if we have an empty fork to use
            for (f_index, fork) in forks.iter().enumerate() {
                if fork.proposals.is_empty() {
                    return Ok((forks[f_index].full_clone()?, Some(f_index)))
                }
            }

            // Generate a new fork extending canonical
            let fork = Fork::new(self.blockchain.clone(), self.module.read().await.clone()).await?;
            return Ok((fork, None))
        }

        let (f_index, p_index) = found.unwrap();
        let original_fork = &forks[f_index];
        // Check if proposal extends fork at last proposal
        if p_index == (original_fork.proposals.len() - 1) {
            return Ok((original_fork.full_clone()?, Some(f_index)))
        }

        // Rebuild fork
        let mut fork = Fork::new(self.blockchain.clone(), self.module.read().await.clone()).await?;
        fork.proposals = original_fork.proposals[..p_index + 1].to_vec();
        fork.diffs = original_fork.diffs[..p_index + 1].to_vec();

        // Retrieve proposals blocks from original fork
        let blocks = &original_fork.overlay.lock().unwrap().get_blocks_by_hash(&fork.proposals)?;
        for (index, block) in blocks.iter().enumerate() {
            // Apply block diffs
            fork.overlay.lock().unwrap().overlay.lock().unwrap().add_diff(&fork.diffs[index])?;

            // Grab next mine target and difficulty
            let (next_target, next_difficulty) = fork.module.next_mine_target_and_difficulty()?;

            // Calculate block rank
            let (target_distance_sq, hash_distance_sq) = block_rank(block, &next_target);

            // Update PoW module
            fork.module.append(block.header.timestamp, &next_difficulty);

            // Update fork ranks
            fork.targets_rank += target_distance_sq;
            fork.hashes_rank += hash_distance_sq;
        }

        // Drop forks lock
        drop(forks);

        Ok((fork, None))
    }

    /// Check if best fork proposals can be finalized.
    /// Consensus finalization logic:
    /// - If the current best fork has reached greater length than the security threshold,
    ///   and no other fork exist with same rank, first proposal(s) in that fork can be
    ///   appended to canonical blockchain (finalize).
    ///
    /// When best fork can be finalized, first block(s) should be appended to canonical,
    /// and forks should be rebuilt.
    pub async fn finalization(&self) -> Result<Option<usize>> {
        debug!(target: "validator::consensus::finalization", "Started finalization check");

        // Grab best fork
        let forks = self.forks.read().await;
        let index = best_fork_index(&forks)?;
        let fork = &forks[index];

        // Check its length
        let length = fork.proposals.len();
        if length < self.finalization_threshold {
            debug!(target: "validator::consensus::finalization", "Nothing to finalize yet, best fork size: {}", length);
            drop(forks);
            return Ok(None)
        }

        // Drop forks lock
        drop(forks);

        Ok(Some(index))
    }

    /// Auxiliary function to retrieve a fork proposals, starting from provided tip.
    /// If provided tip is too far behind, or fork doesn't exists, an empty vector is returned.
    pub async fn get_fork_proposals(
        &self,
        tip: HeaderHash,
        fork_tip: HeaderHash,
        limit: u32,
    ) -> Result<Vec<Proposal>> {
        // Grab a lock over current forks
        let forks = self.forks.read().await;

        // Retrieve our current canonical tip height
        let last_block_height = self.blockchain.last()?.0;

        // Check if request tip is canonical
        let mut canonical_blocks = vec![];
        if let Ok(existing_tip) = self.blockchain.get_blocks_by_hash(&[tip]) {
            // Check tip is not far behind
            if last_block_height - existing_tip[0].header.height >= limit {
                drop(forks);
                return Ok(canonical_blocks)
            }

            // Retrieve all tips after requested one
            let headers = self.blockchain.blocks.get_all_after(existing_tip[0].header.height)?;
            let blocks = self.blockchain.get_blocks_by_hash(&headers)?;

            // Add everything to the return vec
            for block in blocks {
                canonical_blocks.push(Proposal::new(block));
            }
        }

        // Find the fork containing the requested tip and grab its sequence
        let mut proposals = vec![];
        for fork in forks.iter() {
            let mut found = false;
            for p in fork.proposals.iter().rev() {
                if p != &fork_tip {
                    continue
                }
                found = true;
                break
            }

            if !found {
                continue
            }

            let mut headers = vec![];
            for p in &fork.proposals {
                headers.push(*p);
                if p == &fork_tip {
                    break
                }
            }

            let blocks = fork.overlay.lock().unwrap().get_blocks_by_hash(&headers)?;
            for block in blocks {
                proposals.push(Proposal::new(block));
            }
        }

        // Check if we found anything.
        // Even if we found canonical blocks, if the
        // request doesn't correspond to a known fork
        // we return an empty vector.
        if proposals.is_empty() {
            drop(forks);
            return Ok(proposals)
        }

        // Join the two vectors and return them
        canonical_blocks.append(&mut proposals);
        drop(forks);
        Ok(canonical_blocks)
    }

    /// Auxiliary function to retrieve current best fork last header.
    /// If no forks exist, grab the last header from canonical.
    pub async fn best_fork_last_header(&self) -> Result<(u32, HeaderHash)> {
        // Grab a lock over current forks
        let forks = self.forks.read().await;

        // Check if node has any forks
        if forks.is_empty() {
            drop(forks);
            return self.blockchain.last()
        }

        // Grab best fork
        let fork = &forks[best_fork_index(&forks)?];

        // Grab its last header
        let last = fork.last_proposal()?;
        drop(forks);
        Ok((last.block.header.height, last.hash))
    }

    /// Auxiliary function to retrieve current best fork proposals, starting from provided tip.
    /// If provided tip is too far behind, or fork doesn't exists, an empty vector is returned.
    pub async fn get_best_fork_proposals(
        &self,
        tip: HeaderHash,
        limit: u32,
    ) -> Result<Vec<Proposal>> {
        // Grab a lock over current forks
        let forks = self.forks.read().await;

        // Check if node has any forks
        if forks.is_empty() {
            drop(forks);
            return Ok(vec![])
        }

        // Retrieve our current canonical tip height
        let last_block_height = self.blockchain.last()?.0;

        // Check if request tip is canonical
        let mut canonical_blocks = vec![];
        if let Ok(existing_tip) = self.blockchain.get_blocks_by_hash(&[tip]) {
            // Check tip is not far behind
            if last_block_height - existing_tip[0].header.height >= limit {
                drop(forks);
                return Ok(canonical_blocks)
            }

            // Retrieve all tips after requested one
            let headers = self.blockchain.blocks.get_all_after(existing_tip[0].header.height)?;
            let blocks = self.blockchain.get_blocks_by_hash(&headers)?;

            // Add everything to the return vec
            for block in blocks {
                canonical_blocks.push(Proposal::new(block));
            }
        }

        // Grab best fork
        let fork = &forks[best_fork_index(&forks)?];

        // Grab its proposals
        let blocks = fork.overlay.lock().unwrap().get_blocks_by_hash(&fork.proposals)?;
        let mut proposals = Vec::with_capacity(blocks.len());
        for block in blocks {
            proposals.push(Proposal::new(block));
        }

        // Join the two vectors and return them
        canonical_blocks.append(&mut proposals);
        drop(forks);
        Ok(canonical_blocks)
    }

    /// Auxiliary function to purge current forks and reset the ones starting
    /// with the provided prefix, excluding provided finalized fork.
    /// Additionally, remove finalized transactions from the forks mempools,
    /// along with the unporposed transactions sled trees.
    /// This function assumes that the prefix blocks have already been appended
    /// to canonical chain from the finalized fork.
    pub async fn reset_forks(
        &self,
        prefix: &[HeaderHash],
        finalized_fork_index: &usize,
        finalized_txs: &[Transaction],
    ) -> Result<()> {
        // Grab a lock over current forks
        let mut forks = self.forks.write().await;

        // Find all the forks that start with the provided prefix,
        // excluding finalized fork index, and remove their prefixed
        // proposals, and their corresponding diffs.
        // If the fork is not starting with the provided prefix,
        // drop it. Additionally, keep track of all the referenced
        // trees in overlays that are valid.
        let excess = prefix.len();
        let prefix_last_index = excess - 1;
        let prefix_last = prefix.last().unwrap();
        let mut keep = vec![true; forks.len()];
        let mut referenced_trees = HashSet::new();
        let mut referenced_txs = HashSet::new();
        let finalized_txs_hashes: Vec<TransactionHash> =
            finalized_txs.iter().map(|tx| tx.hash()).collect();
        for (index, fork) in forks.iter_mut().enumerate() {
            if &index == finalized_fork_index {
                // Store its tree references
                let fork_overlay = fork.overlay.lock().unwrap();
                let overlay = fork_overlay.overlay.lock().unwrap();
                for tree in &overlay.state.initial_tree_names {
                    referenced_trees.insert(tree.clone());
                }
                for tree in &overlay.state.new_tree_names {
                    referenced_trees.insert(tree.clone());
                }
                for tree in overlay.state.dropped_trees.keys() {
                    referenced_trees.insert(tree.clone());
                }
                // Remove finalized proposals txs from fork's mempool
                fork.mempool.retain(|tx| !finalized_txs_hashes.contains(tx));
                // Store its txs references
                for tx in &fork.mempool {
                    referenced_txs.insert(*tx);
                }
                drop(overlay);
                drop(fork_overlay);
                continue
            }

            if fork.proposals.is_empty() ||
                prefix_last_index >= fork.proposals.len() ||
                &fork.proposals[prefix_last_index] != prefix_last
            {
                keep[index] = false;
                continue
            }

            // Remove finalized proposals txs from fork's mempool
            fork.mempool.retain(|tx| !finalized_txs_hashes.contains(tx));
            // Store its txs references
            for tx in &fork.mempool {
                referenced_txs.insert(*tx);
            }

            // Remove the commited differences
            let rest_proposals = fork.proposals.split_off(excess);
            let rest_diffs = fork.diffs.split_off(excess);
            let mut diffs = fork.diffs.clone();
            fork.proposals = rest_proposals;
            fork.diffs = rest_diffs;
            for diff in diffs.iter_mut() {
                fork.overlay.lock().unwrap().overlay.lock().unwrap().remove_diff(diff);
            }

            // Store its tree references
            let fork_overlay = fork.overlay.lock().unwrap();
            let overlay = fork_overlay.overlay.lock().unwrap();
            for tree in &overlay.state.initial_tree_names {
                referenced_trees.insert(tree.clone());
            }
            for tree in &overlay.state.new_tree_names {
                referenced_trees.insert(tree.clone());
            }
            for tree in overlay.state.dropped_trees.keys() {
                referenced_trees.insert(tree.clone());
            }
            drop(overlay);
            drop(fork_overlay);
        }

        // Find the trees and pending txs that are no longer referenced by valid forks
        let mut dropped_trees = HashSet::new();
        let mut dropped_txs = HashSet::new();
        for (index, fork) in forks.iter_mut().enumerate() {
            if keep[index] {
                continue
            }
            for tx in &fork.mempool {
                if !referenced_txs.contains(tx) {
                    dropped_txs.insert(*tx);
                }
            }
            let fork_overlay = fork.overlay.lock().unwrap();
            let overlay = fork_overlay.overlay.lock().unwrap();
            for tree in &overlay.state.initial_tree_names {
                if !referenced_trees.contains(tree) {
                    dropped_trees.insert(tree.clone());
                }
            }
            for tree in &overlay.state.new_tree_names {
                if !referenced_trees.contains(tree) {
                    dropped_trees.insert(tree.clone());
                }
            }
            for tree in overlay.state.dropped_trees.keys() {
                if !referenced_trees.contains(tree) {
                    dropped_trees.insert(tree.clone());
                }
            }
            drop(overlay);
            drop(fork_overlay);
        }

        // Drop unreferenced trees from the database
        for tree in dropped_trees {
            self.blockchain.sled_db.drop_tree(tree)?;
        }

        // Drop invalid forks
        let mut iter = keep.iter();
        forks.retain(|_| *iter.next().unwrap());

        // Remove finalized proposals txs from the unporposed txs sled tree
        self.blockchain.remove_pending_txs_hashes(&finalized_txs_hashes)?;

        // Remove unreferenced txs from the unporposed txs sled tree
        self.blockchain.remove_pending_txs_hashes(&Vec::from_iter(dropped_txs))?;

        // Drop forks lock
        drop(forks);

        Ok(())
    }

    /// Auxiliary function to fully purge current forks and leave only a new empty fork.
    pub async fn purge_forks(&self) -> Result<()> {
        debug!(target: "validator::consensus::purge_forks", "Purging current forks...");
        let mut forks = self.forks.write().await;
        *forks = vec![Fork::new(self.blockchain.clone(), self.module.read().await.clone()).await?];
        drop(forks);
        debug!(target: "validator::consensus::purge_forks", "Forks purged!");
        Ok(())
    }

    /// Auxiliary function to reset PoW module.
    pub async fn reset_pow_module(&self) -> Result<()> {
        debug!(target: "validator::consensus::reset_pow_module", "Resetting PoW module...");
        let mut module = self.module.write().await;
        *module = PoWModule::new(
            self.blockchain.clone(),
            module.target,
            module.fixed_difficulty.clone(),
        )?;
        drop(module);
        debug!(target: "validator::consensus::reset_pow_module", "PoW module reset successfully!");
        Ok(())
    }
}

/// This struct represents a block proposal, used for consensus.
#[derive(Debug, Clone, SerialEncodable, SerialDecodable)]
pub struct Proposal {
    /// Block hash
    pub hash: HeaderHash,
    /// Block data
    pub block: BlockInfo,
}

impl Proposal {
    pub fn new(block: BlockInfo) -> Self {
        let hash = block.hash();
        Self { hash, block }
    }
}

impl From<Proposal> for BlockInfo {
    fn from(proposal: Proposal) -> BlockInfo {
        proposal.block
    }
}

/// Struct representing a forked blockchain state.
///
/// An overlay over the original blockchain is used, containing all pending to-write
/// records. Additionally, each fork keeps a vector of valid pending transactions hashes,
/// in order of receival, and the proposals hashes sequence, for validations.
#[derive(Clone)]
pub struct Fork {
    /// Canonical (finalized) blockchain
    pub blockchain: Blockchain,
    /// Overlay cache over canonical Blockchain
    pub overlay: BlockchainOverlayPtr,
    /// Current PoW module state,
    pub module: PoWModule,
    /// Fork proposal hashes sequence
    pub proposals: Vec<HeaderHash>,
    /// Fork proposal overlay diffs sequence
    pub diffs: Vec<SledDbOverlayStateDiff>,
    /// Valid pending transaction hashes
    pub mempool: Vec<TransactionHash>,
    /// Current fork mining targets rank, cached for better performance
    pub targets_rank: BigUint,
    /// Current fork hashes rank, cached for better performance
    pub hashes_rank: BigUint,
}

impl Fork {
    pub async fn new(blockchain: Blockchain, module: PoWModule) -> Result<Self> {
        let mempool = blockchain.get_pending_txs()?.iter().map(|tx| tx.hash()).collect();
        let overlay = BlockchainOverlay::new(&blockchain)?;
        // Retrieve last block difficulty to access current ranks
        let last_difficulty = blockchain.last_block_difficulty()?;
        let targets_rank = last_difficulty.ranks.targets_rank;
        let hashes_rank = last_difficulty.ranks.hashes_rank;
        Ok(Self {
            blockchain,
            overlay,
            module,
            proposals: vec![],
            diffs: vec![],
            mempool,
            targets_rank,
            hashes_rank,
        })
    }

    /// Auxiliary function to append a proposal and update current fork rank.
    pub async fn append_proposal(&mut self, proposal: &Proposal) -> Result<()> {
        // Grab next mine target and difficulty
        let (next_target, next_difficulty) = self.module.next_mine_target_and_difficulty()?;

        // Calculate block rank
        let (target_distance_sq, hash_distance_sq) = block_rank(&proposal.block, &next_target);

        // Update fork ranks
        self.targets_rank += target_distance_sq.clone();
        self.hashes_rank += hash_distance_sq.clone();

        // Generate block difficulty and update PoW module
        let cummulative_difficulty =
            self.module.cummulative_difficulty.clone() + next_difficulty.clone();
        let ranks = BlockRanks::new(
            target_distance_sq,
            self.targets_rank.clone(),
            hash_distance_sq,
            self.hashes_rank.clone(),
        );
        let block_difficulty = BlockDifficulty::new(
            proposal.block.header.height,
            proposal.block.header.timestamp,
            next_difficulty,
            cummulative_difficulty,
            ranks,
        );
        self.module.append_difficulty(&self.overlay, block_difficulty)?;

        // Push proposal's hash
        self.proposals.push(proposal.hash);

        // Push proposal overlay diff
        self.diffs.push(self.overlay.lock().unwrap().overlay.lock().unwrap().diff(&self.diffs)?);

        Ok(())
    }

    /// Auxiliary function to retrieve last proposal.
    pub fn last_proposal(&self) -> Result<Proposal> {
        let block = if let Some(last) = self.proposals.last() {
            self.overlay.lock().unwrap().get_blocks_by_hash(&[*last])?[0].clone()
        } else {
            self.overlay.lock().unwrap().last_block()?
        };

        Ok(Proposal::new(block))
    }

    /// Auxiliary function to compute forks' next block height.
    pub fn get_next_block_height(&self) -> Result<u32> {
        let proposal = self.last_proposal()?;
        Ok(proposal.block.header.height + 1)
    }

    /// Auxiliary function to retrieve unproposed valid transactions,
    /// along with their total gas used and total paid fees.
    pub async fn unproposed_txs(
        &self,
        blockchain: &Blockchain,
        verifying_block_height: u32,
        block_target: u32,
        verify_fees: bool,
    ) -> Result<(Vec<Transaction>, u64, u64)> {
        // Check if our mempool is not empty
        if self.mempool.is_empty() {
            return Ok((vec![], 0, 0))
        }

        // Transactions Merkle tree
        let mut tree = MerkleTree::new(1);

        // Total gas accumulators
        let mut total_gas_used = 0;
        let mut total_gas_paid = 0;

        // Map of ZK proof verifying keys for the current transaction batch
        let mut vks: HashMap<[u8; 32], HashMap<String, VerifyingKey>> = HashMap::new();

        // Clone forks' overlay
        let overlay = self.overlay.lock().unwrap().full_clone()?;

        // Grab all current proposals transactions hashes
        let proposals_txs = overlay.lock().unwrap().get_blocks_txs_hashes(&self.proposals)?;

        // Iterate through all pending transactions in the forks' mempool
        let mut unproposed_txs = vec![];
        for tx in &self.mempool {
            // If the hash is contained in the proposals transactions vec, skip it
            if proposals_txs.contains(tx) {
                continue
            }

            // Retrieve the actual unproposed transaction
            let unproposed_tx =
                blockchain.transactions.get_pending(&[*tx], true)?[0].clone().unwrap();

            // Update the verifying keys map
            for call in &unproposed_tx.calls {
                vks.entry(call.data.contract_id.to_bytes()).or_default();
            }

            // Verify the transaction against current state
            overlay.lock().unwrap().checkpoint();
            let (tx_gas_used, tx_gas_paid) = match verify_transaction(
                &overlay,
                verifying_block_height,
                block_target,
                &unproposed_tx,
                &mut tree,
                &mut vks,
                verify_fees,
            )
            .await
            {
                Ok(gas_values) => gas_values,
                Err(e) => {
                    debug!(target: "validator::consensus::unproposed_txs", "Transaction verification failed: {}", e);
                    overlay.lock().unwrap().revert_to_checkpoint()?;
                    continue
                }
            };

            // Calculate current accumulated gas usage
            let accumulated_gas_usage = total_gas_used + tx_gas_used;

            // Check gas limit - if accumulated gas used exceeds it, break out of loop
            if accumulated_gas_usage > GAS_LIMIT_UNPROPOSED_TXS {
                warn!(target: "validator::consensus::unproposed_txs", "Retrieving transaction {} would exceed configured unproposed transaction gas limit: {} - {}", tx, accumulated_gas_usage, GAS_LIMIT_UNPROPOSED_TXS);
                break
            }

            // Update accumulated total gas
            total_gas_used += tx_gas_used;
            total_gas_paid += tx_gas_paid;

            // Push the tx hash into the unproposed transactions vector
            unproposed_txs.push(unproposed_tx);
        }

        Ok((unproposed_txs, total_gas_used, total_gas_paid))
    }

    /// Auxiliary function to create a full clone using BlockchainOverlay::full_clone.
    /// Changes to this copy don't affect original fork overlay records, since underlying
    /// overlay pointer have been updated to the cloned one.
    pub fn full_clone(&self) -> Result<Self> {
        let blockchain = self.blockchain.clone();
        let overlay = self.overlay.lock().unwrap().full_clone()?;
        let module = self.module.clone();
        let proposals = self.proposals.clone();
        let diffs = self.diffs.clone();
        let mempool = self.mempool.clone();
        let targets_rank = self.targets_rank.clone();
        let hashes_rank = self.hashes_rank.clone();

        Ok(Self {
            blockchain,
            overlay,
            module,
            proposals,
            diffs,
            mempool,
            targets_rank,
            hashes_rank,
        })
    }
}
