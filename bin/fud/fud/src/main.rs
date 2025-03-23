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

use std::{
    collections::{HashMap, HashSet},
    io::ErrorKind,
    path::PathBuf,
    sync::Arc,
};

use num_bigint::BigUint;
use rpc::{ChunkDownloadCompleted, ChunkNotFound};
use tasks::FetchReply;

use crate::rpc::FudEvent;
use async_trait::async_trait;
use dht::{Dht, DhtHandler, DhtNode, DhtRouterItem, DhtRouterPtr};
use futures::{future::FutureExt, pin_mut, select};
use log::{debug, error, info, warn};
use rand::{prelude::IteratorRandom, rngs::OsRng, seq::SliceRandom, RngCore};
use smol::{
    channel,
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
    lock::{Mutex, RwLock},
    stream::StreamExt,
    Executor,
};
use structopt_toml::{structopt::StructOpt, StructOptToml};

use darkfi::{
    async_daemonize, cli_desc,
    geode::{hash_to_string, Geode},
    net::{session::SESSION_DEFAULT, settings::SettingsOpt, ChannelPtr, P2p, P2pPtr},
    rpc::{
        jsonrpc::JsonSubscriber,
        p2p_method::HandlerP2p,
        server::{listen_and_serve, RequestHandler},
        settings::{RpcSettings, RpcSettingsOpt},
    },
    system::{Publisher, PublisherPtr, StoppableTask, StoppableTaskPtr},
    util::path::expand_path,
    Error, Result,
};

/// P2P protocols
mod proto;
use proto::{
    FudAnnounce, FudChunkReply, FudFileReply, FudFindNodesReply, FudFindNodesRequest,
    FudFindRequest, FudFindSeedersReply, FudFindSeedersRequest, FudNotFound, FudPingReply,
    FudPingRequest, ProtocolFud,
};

mod dht;
mod rpc;
mod tasks;

const CONFIG_FILE: &str = "fud_config.toml";
const CONFIG_FILE_CONTENTS: &str = include_str!("../fud_config.toml");

const NODE_ID_PATH: &str = "node_id";

#[derive(Clone, Debug, serde::Deserialize, StructOpt, StructOptToml)]
#[serde(default)]
#[structopt(name = "fud", about = cli_desc!())]
struct Args {
    #[structopt(short, parse(from_occurrences))]
    /// Increase verbosity (-vvv supported)
    verbose: u8,

    #[structopt(short, long)]
    /// Configuration file to use
    config: Option<String>,

    #[structopt(long)]
    /// Set log file path to output daemon logs into
    log: Option<String>,

    #[structopt(long, default_value = "~/.local/share/darkfi/fud")]
    /// Base directory for filesystem storage
    base_dir: String,

    #[structopt(flatten)]
    /// Network settings
    net: SettingsOpt,

    #[structopt(flatten)]
    /// JSON-RPC settings
    rpc: RpcSettingsOpt,
}

pub struct Fud {
    /// Key -> Seeders
    seeders_router: DhtRouterPtr,

    /// Pointer to the P2P network instance
    p2p: P2pPtr,

    /// The Geode instance
    geode: Geode,

    /// The DHT instance
    dht: Arc<Dht>,

    get_tx: channel::Sender<(u16, blake3::Hash, Option<String>, Result<()>)>,
    get_rx: channel::Receiver<(u16, blake3::Hash, Option<String>, Result<()>)>,
    file_fetch_tx: channel::Sender<(blake3::Hash, Result<()>)>,
    file_fetch_rx: channel::Receiver<(blake3::Hash, Result<()>)>,
    file_fetch_end_tx: channel::Sender<(blake3::Hash, Result<()>)>,
    file_fetch_end_rx: channel::Receiver<(blake3::Hash, Result<()>)>,

    rpc_connections: Mutex<HashSet<StoppableTaskPtr>>,

    /// dnet JSON-RPC subscriber
    dnet_sub: JsonSubscriber,

    /// Download JSON-RPC subscriber
    download_sub: JsonSubscriber,

    download_publisher: PublisherPtr<FudEvent>,
}

impl HandlerP2p for Fud {
    fn p2p(&self) -> P2pPtr {
        self.p2p.clone()
    }
}

#[async_trait]
impl DhtHandler for Fud {
    fn dht(&self) -> Arc<Dht> {
        self.dht.clone()
    }

    async fn ping(&self, channel: ChannelPtr) -> Result<dht::DhtNode> {
        debug!(target: "fud::DhtHandler::ping()", "Sending ping to channel {}", channel.info.id);
        let msg_subsystem = channel.message_subsystem();
        msg_subsystem.add_dispatch::<FudPingReply>().await;
        let msg_subscriber = channel.subscribe_msg::<FudPingReply>().await.unwrap();
        let request = FudPingRequest {};

        channel.send(&request).await?;

        let reply = msg_subscriber.receive_with_timeout(self.dht().timeout).await?;

        msg_subscriber.unsubscribe().await;

        Ok(reply.node.clone())
    }

    // TODO: Optimize this
    async fn on_new_node(&self, node: &DhtNode) -> Result<()> {
        debug!(target: "fud::DhtHandler::on_new_node()", "New node {}", hash_to_string(&node.id));

        // If this is the first node we know about, then bootstrap
        if !self.dht().is_bootstrapped().await {
            self.dht().set_bootstrapped().await;

            // Lookup our own node id
            let self_node = self.dht().node.clone();
            debug!(target: "fud::DhtHandler::on_new_node()", "DHT bootstrapping {}", hash_to_string(&self_node.id));
            let _ = self.lookup_nodes(&self_node.id).await;
        }

        // Send keys that are closer to this node than we are
        let self_id = self.dht().node.id;
        let channel = self.get_channel(node).await?;
        for (key, seeders) in self.seeders_router.read().await.iter() {
            let node_distance = BigUint::from_bytes_be(&self.dht().distance(key, &node.id));
            let self_distance = BigUint::from_bytes_be(&self.dht().distance(key, &self_id));
            if node_distance <= self_distance {
                let _ = channel
                    .send(&FudAnnounce {
                        key: *key,
                        seeders: seeders.clone().into_iter().collect(),
                    })
                    .await;
            }
        }

        Ok(())
    }

    async fn fetch_nodes(&self, node: &DhtNode, key: &blake3::Hash) -> Result<Vec<DhtNode>> {
        debug!(target: "fud::DhtHandler::fetch_value()", "Fetching nodes close to {} from node {}", hash_to_string(key), hash_to_string(&node.id));

        let channel = self.get_channel(node).await?;
        let msg_subsystem = channel.message_subsystem();
        msg_subsystem.add_dispatch::<FudFindNodesReply>().await;
        let msg_subscriber_nodes = channel.subscribe_msg::<FudFindNodesReply>().await.unwrap();

        let request = FudFindNodesRequest { key: *key };
        channel.send(&request).await?;

        let reply = msg_subscriber_nodes.receive_with_timeout(self.dht().timeout).await?;

        msg_subscriber_nodes.unsubscribe().await;

        Ok(reply.nodes.clone())
    }
}

impl Fud {
    /// Add ourselves to `seeders_router` for the files we already have.
    /// Skipped if we have no external address.
    async fn init(&self) -> Result<()> {
        if self.dht().node.clone().addresses.is_empty() {
            return Ok(());
        }
        let self_router_items: Vec<DhtRouterItem> = vec![self.dht().node.clone().into()];
        let hashes = self.geode.list_files().await?;

        for hash in hashes {
            self.add_to_router(self.seeders_router.clone(), &hash, self_router_items.clone()).await;
        }

        Ok(())
    }

    /// Query nodes close to `key` to find the seeders
    async fn fetch_seeders(&self, key: blake3::Hash) -> HashSet<DhtRouterItem> {
        let closest_nodes = self.lookup_nodes(&key).await; // Find the `k` closest nodes
        if closest_nodes.is_err() {
            return HashSet::new();
        }

        let mut seeders: HashSet<DhtRouterItem> = HashSet::new();

        for node in closest_nodes.unwrap() {
            let channel = match self.get_channel(&node).await {
                Ok(channel) => channel,
                Err(e) => {
                    warn!(target: "fud::fetch_seeders()", "Could not get a channel for node {}: {}", hash_to_string(&node.id), e);
                    continue;
                }
            };
            let msg_subsystem = channel.message_subsystem();
            msg_subsystem.add_dispatch::<FudFindSeedersReply>().await;

            let msg_subscriber = match channel.subscribe_msg::<FudFindSeedersReply>().await {
                Ok(msg_subscriber) => msg_subscriber,
                Err(e) => {
                    warn!(target: "fud::fetch_seeders()", "Error subscribing to msg: {}", e);
                    continue;
                }
            };

            let send_res = channel.send(&FudFindSeedersRequest { key }).await;
            if let Err(e) = send_res {
                warn!(target: "fud::fetch_seeders()", "Error while sending FudFindSeedersRequest: {}", e);
                msg_subscriber.unsubscribe().await;
                continue;
            }

            let reply = match msg_subscriber.receive_with_timeout(self.dht().timeout).await {
                Ok(reply) => reply,
                Err(e) => {
                    warn!(target: "fud::fetch_seeders()", "Error waiting for reply: {}", e);
                    msg_subscriber.unsubscribe().await;
                    continue;
                }
            };

            msg_subscriber.unsubscribe().await;

            seeders.extend(reply.seeders.clone());
        }

        info!(target: "fud::fetch_seeders()", "Found {} seeders for {}", seeders.len(), hash_to_string(&key));
        seeders
    }

    /// Fetch chunks for a file from `seeders`
    async fn fetch_chunks(
        &self,
        file_hash: &blake3::Hash,
        chunk_hashes: &HashSet<blake3::Hash>,
        seeders: &HashSet<DhtRouterItem>,
    ) {
        let mut remaining_chunks = chunk_hashes.clone();
        let mut shuffled_seeders = {
            let mut vec: Vec<_> = seeders.iter().cloned().collect();
            vec.shuffle(&mut OsRng);
            vec
        };

        while let Some(seeder) = shuffled_seeders.pop() {
            let channel = match self.get_channel(&seeder.node).await {
                Ok(channel) => channel,
                Err(e) => {
                    warn!(target: "fud::fetch_chunks()", "Could not get a channel for node {}: {}", hash_to_string(&seeder.node.id), e);
                    continue;
                }
            };
            info!("Requesting chunks from seeder {}", hash_to_string(&seeder.node.id));
            loop {
                let msg_subsystem = channel.message_subsystem();
                msg_subsystem.add_dispatch::<FudChunkReply>().await;
                msg_subsystem.add_dispatch::<FudNotFound>().await;
                let msg_subscriber_chunk = channel.subscribe_msg::<FudChunkReply>().await.unwrap();
                let msg_subscriber_notfound = channel.subscribe_msg::<FudNotFound>().await.unwrap();

                let mut chunks_to_query = remaining_chunks.clone();

                // Select a chunk to request
                let mut chunk_hash: Option<blake3::Hash> = None;
                if let Some(&random_chunk) = chunks_to_query.iter().choose(&mut OsRng) {
                    chunk_hash = Some(random_chunk);
                }

                if chunk_hash.is_none() {
                    // No more chunks to request from this seeder
                    break; // Switch to another seeder
                }
                let chunk_hash = chunk_hash.unwrap();

                let send_res = channel.send(&FudFindRequest { key: chunk_hash }).await;
                if let Err(e) = send_res {
                    warn!(target: "fud::fetch_chunks()", "Error while sending FudFindRequest: {}", e);
                    break; // Switch to another seeder
                }

                let chunk_recv =
                    msg_subscriber_chunk.receive_with_timeout(self.dht().timeout).fuse();
                let notfound_recv =
                    msg_subscriber_notfound.receive_with_timeout(self.dht().timeout).fuse();

                pin_mut!(chunk_recv, notfound_recv);

                // Wait for a FudChunkReply or FudNotFound
                select! {
                    chunk_reply = chunk_recv => {
                        if let Err(e) = chunk_reply {
                            warn!(target: "fud::fetch_chunks()", "Error waiting for chunk reply: {}", e);
                            break; // Switch to another seeder
                        }
                        chunks_to_query.remove(&chunk_hash);
                        let reply = chunk_reply.unwrap();

                        match self.geode.insert_chunk(&reply.chunk).await {
                            Ok(inserted_hash) => {
                                if inserted_hash != chunk_hash {
                                    warn!("Received chunk does not match requested chunk");
                                    msg_subscriber_chunk.unsubscribe().await;
                                    msg_subscriber_notfound.unsubscribe().await;
                                    continue; // Skip to next chunk, will retry this chunk later
                                }

                                info!(target: "fud::fetch_chunks()", "Received chunk {} from seeder {}", hash_to_string(&chunk_hash), hash_to_string(&seeder.node.id));
                                self.download_publisher
                                    .notify(FudEvent::ChunkDownloadCompleted(ChunkDownloadCompleted {
                                        file_hash: *file_hash,
                                        chunk_hash,
                                    }))
                                    .await;
                                remaining_chunks.remove(&chunk_hash);
                            }
                            Err(e) => {
                                error!("Failed inserting chunk {} to Geode: {}", hash_to_string(&chunk_hash), e);
                            }
                        };
                    }
                    notfound_reply = notfound_recv => {
                        if let Err(e) = notfound_reply {
                            warn!(target: "fud::fetch_chunks()", "Error waiting for NOTFOUND reply: {}", e);
                            msg_subscriber_chunk.unsubscribe().await;
                            msg_subscriber_notfound.unsubscribe().await;
                            break; // Switch to another seeder
                        }
                        info!(target: "fud::fetch_chunks()", "Received NOTFOUND {} from seeder {}", hash_to_string(&chunk_hash), hash_to_string(&seeder.node.id));
                        self.download_publisher
                            .notify(FudEvent::ChunkNotFound(ChunkNotFound {
                                file_hash: *file_hash,
                                chunk_hash,
                            }))
                        .await;
                        chunks_to_query.remove(&chunk_hash);
                    }
                };

                msg_subscriber_chunk.unsubscribe().await;
                msg_subscriber_notfound.unsubscribe().await;
            }

            // Stop when there are no missing chunks
            if remaining_chunks.is_empty() {
                break;
            }
        }
    }

    /// Fetch a single file metadata from the network.
    /// If the file is smaller than a single chunk then the chunk is returned.
    /// 1. Lookup nodes close to the key
    /// 2. Request seeders for the file from those nodes
    /// 3. Request the file from the seeders
    async fn fetch_file_metadata(&self, file_hash: blake3::Hash) -> Option<FetchReply> {
        let mut queried_seeders: HashSet<blake3::Hash> = HashSet::new();
        let closest_nodes = self.lookup_nodes(&file_hash).await; // 1
        let mut result: Option<FetchReply> = None;
        if closest_nodes.is_err() {
            return None
        }

        for node in closest_nodes.unwrap() {
            // 2. Request list of seeders
            let channel = match self.get_channel(&node).await {
                Ok(channel) => channel,
                Err(e) => {
                    warn!(target: "fud::fetch_file_metadata()", "Could not get a channel for node {}: {}", hash_to_string(&node.id), e);
                    continue;
                }
            };
            let msg_subsystem = channel.message_subsystem();
            msg_subsystem.add_dispatch::<FudFindSeedersReply>().await;

            let msg_subscriber = match channel.subscribe_msg::<FudFindSeedersReply>().await {
                Ok(msg_subscriber) => msg_subscriber,
                Err(e) => {
                    warn!(target: "fud::fetch_file_metadata()", "Error subscribing to msg: {}", e);
                    continue;
                }
            };

            let send_res = channel.send(&FudFindSeedersRequest { key: file_hash }).await;
            if let Err(e) = send_res {
                warn!(target: "fud::fetch_file_metadata()", "Error while sending FudFindSeedersRequest: {}", e);
                msg_subscriber.unsubscribe().await;
                continue;
            }

            let reply = match msg_subscriber.receive_with_timeout(self.dht().timeout).await {
                Ok(reply) => reply,
                Err(e) => {
                    warn!(target: "fud::fetch_file_metadata()", "Error waiting for reply: {}", e);
                    msg_subscriber.unsubscribe().await;
                    continue;
                }
            };

            let mut seeders = reply.seeders.clone();
            info!(target: "fud::fetch_file_metadata()", "Found {} seeders for {}", seeders.len(), hash_to_string(&file_hash));

            msg_subscriber.unsubscribe().await;

            // 3. Request the file/chunk from the seeders
            while let Some(seeder) = seeders.pop() {
                // Only query a seeder once
                if queried_seeders.iter().any(|s| *s == seeder.node.id) {
                    continue;
                }
                queried_seeders.insert(seeder.node.id);

                if let Ok(channel) = self.get_channel(&seeder.node).await {
                    let msg_subsystem = channel.message_subsystem();
                    msg_subsystem.add_dispatch::<FudChunkReply>().await;
                    msg_subsystem.add_dispatch::<FudFileReply>().await;
                    msg_subsystem.add_dispatch::<FudNotFound>().await;
                    let msg_subscriber_chunk =
                        channel.subscribe_msg::<FudChunkReply>().await.unwrap();
                    let msg_subscriber_file =
                        channel.subscribe_msg::<FudFileReply>().await.unwrap();
                    let msg_subscriber_notfound =
                        channel.subscribe_msg::<FudNotFound>().await.unwrap();

                    let send_res = channel.send(&FudFindRequest { key: file_hash }).await;
                    if let Err(e) = send_res {
                        warn!(target: "fud::fetch_file_metadata()", "Error while sending FudFindRequest: {}", e);
                        msg_subscriber_chunk.unsubscribe().await;
                        msg_subscriber_file.unsubscribe().await;
                        msg_subscriber_notfound.unsubscribe().await;
                        continue;
                    }

                    let chunk_recv =
                        msg_subscriber_chunk.receive_with_timeout(self.dht().timeout).fuse();
                    let file_recv =
                        msg_subscriber_file.receive_with_timeout(self.dht().timeout).fuse();
                    let notfound_recv =
                        msg_subscriber_notfound.receive_with_timeout(self.dht().timeout).fuse();

                    pin_mut!(chunk_recv, file_recv, notfound_recv);

                    let cleanup = async || {
                        msg_subscriber_chunk.unsubscribe().await;
                        msg_subscriber_file.unsubscribe().await;
                        msg_subscriber_notfound.unsubscribe().await;
                    };

                    // Wait for a FudChunkReply, FudFileReply, or FudNotFound
                    select! {
                        // Received a chunk while requesting a file, this is allowed to
                        // optimize fetching files smaller than a single chunk
                        chunk_reply = chunk_recv => {
                            cleanup().await;
                            if let Err(e) = chunk_reply {
                                warn!(target: "fud::fetch_file_metadata()", "Error waiting for chunk reply: {}", e);
                                continue;
                            }
                            let reply = chunk_reply.unwrap();
                            let chunk_hash = blake3::hash(&reply.chunk);
                            // Check that this is the only chunk in the file
                            if !self.geode.verify_file(&file_hash, &[chunk_hash]) {
                                warn!(target: "fud::fetch_file_metadata()", "Received a chunk while fetching a file, the chunk did not match the file hash");
                                continue;
                            }
                            info!(target: "fud::fetch_file_metadata()", "Received chunk {} (for file {}) from seeder {}", hash_to_string(&chunk_hash), hash_to_string(&file_hash), hash_to_string(&seeder.node.id));
                            result = Some(FetchReply::Chunk((*reply).clone()));
                            break;
                        }
                        file_reply = file_recv => {
                            cleanup().await;
                            if let Err(e) = file_reply {
                                warn!(target: "fud::fetch_file_metadata()", "Error waiting for file reply: {}", e);
                                continue;
                            }
                            let reply = file_reply.unwrap();
                            if !self.geode.verify_file(&file_hash, &reply.chunk_hashes) {
                                warn!(target: "fud::fetch_file_metadata()", "Received invalid file metadata");
                                continue;
                            }
                            info!(target: "fud::fetch_file_metadata()", "Received file {} from seeder {}", hash_to_string(&file_hash), hash_to_string(&seeder.node.id));
                            result = Some(FetchReply::File((*reply).clone()));
                            break;
                        }
                        notfound_reply = notfound_recv => {
                            cleanup().await;
                            if let Err(e) = notfound_reply {
                                warn!(target: "fud::fetch_file_metadata()", "Error waiting for NOTFOUND reply: {}", e);
                                continue;
                            }
                            info!(target: "fud::fetch_file_metadata()", "Received NOTFOUND {} from seeder {}", hash_to_string(&file_hash), hash_to_string(&seeder.node.id));
                        }
                    };
                }
            }

            if result.is_some() {
                break;
            }
        }

        result
    }
}

// TODO: This is not Sybil-resistant
fn generate_node_id() -> Result<blake3::Hash> {
    let mut rng = OsRng;
    let mut random_data = [0u8; 32];
    rng.fill_bytes(&mut random_data);
    let node_id = blake3::Hash::from_bytes(random_data);
    Ok(node_id)
}

async_daemonize!(realmain);
async fn realmain(args: Args, ex: Arc<Executor<'static>>) -> Result<()> {
    // The working directory for this daemon and geode.
    let basedir = expand_path(&args.base_dir)?;

    // Hashmap used for routing
    let seeders_router = Arc::new(RwLock::new(HashMap::new()));

    info!("Instantiating Geode instance");
    let geode = Geode::new(&basedir).await?;

    info!("Instantiating P2P network");
    let p2p = P2p::new(args.net.into(), ex.clone()).await?;

    let external_addrs = p2p.hosts().external_addrs().await;

    if external_addrs.is_empty() {
        warn!(target: "fud::realmain", "No external addresses, you won't be able to seed")
    }

    info!("Starting dnet subs task");
    let dnet_sub = JsonSubscriber::new("dnet.subscribe_events");
    let dnet_sub_ = dnet_sub.clone();
    let p2p_ = p2p.clone();
    let dnet_task = StoppableTask::new();
    dnet_task.clone().start(
        async move {
            let dnet_sub = p2p_.dnet_subscribe().await;
            loop {
                let event = dnet_sub.receive().await;
                debug!("Got dnet event: {:?}", event);
                dnet_sub_.notify(vec![event.into()].into()).await;
            }
        },
        |res| async {
            match res {
                Ok(()) | Err(Error::DetachedTaskStopped) => { /* Do nothing */ }
                Err(e) => panic!("{}", e),
            }
        },
        Error::DetachedTaskStopped,
        ex.clone(),
    );

    // Get or generate the node id
    let node_id: Result<blake3::Hash> = {
        let mut node_id_path: PathBuf = basedir.clone();
        node_id_path.push(NODE_ID_PATH);
        match File::open(node_id_path.clone()).await {
            Ok(mut file) => {
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer).await?;
                let buf: [u8; 44] = buffer.try_into().expect("Node ID must have 44 characters");
                let mut out_buf = [0u8; 32];
                bs58::decode(buf).onto(&mut out_buf)?;
                let node_id = blake3::Hash::from_bytes(out_buf);
                Ok(node_id)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let node_id = generate_node_id()?;
                let mut file =
                    OpenOptions::new().write(true).create(true).open(node_id_path).await?;
                file.write_all(&bs58::encode(node_id.as_bytes()).into_vec()).await?;
                file.flush().await?;
                Ok(node_id)
            }
            Err(e) => Err(e.into()),
        }
    };

    let node_id_ = node_id?;

    info!(target: "fud", "Your node ID: {}", hash_to_string(&node_id_));

    // Daemon instantiation
    let download_sub = JsonSubscriber::new("get");
    let (get_tx, get_rx) = smol::channel::unbounded();
    let (file_fetch_tx, file_fetch_rx) = smol::channel::unbounded();
    let (file_fetch_end_tx, file_fetch_end_rx) = smol::channel::unbounded();
    // TODO: Add DHT settings in the config file
    let dht = Arc::new(Dht::new(&node_id_, 4, 16, 60, p2p.clone(), ex.clone()).await);
    let fud = Arc::new(Fud {
        seeders_router,
        p2p: p2p.clone(),
        geode,
        dht: dht.clone(),
        get_tx,
        get_rx,
        file_fetch_tx,
        file_fetch_rx,
        file_fetch_end_tx,
        file_fetch_end_rx,
        rpc_connections: Mutex::new(HashSet::new()),
        dnet_sub,
        download_sub: download_sub.clone(),
        download_publisher: Publisher::new(),
    });
    fud.init().await?;

    info!("Starting download subs task");
    let download_sub_ = download_sub.clone();
    let fud_ = fud.clone();
    let download_task = StoppableTask::new();
    download_task.clone().start(
        async move {
            let download_sub = fud_.download_publisher.clone().subscribe().await;
            loop {
                let event = download_sub.receive().await;
                debug!("Got download event: {:?}", event);
                download_sub_.notify(event.into()).await;
            }
        },
        |res| async {
            match res {
                Ok(()) | Err(Error::DetachedTaskStopped) => { /* Do nothing */ }
                Err(e) => panic!("{}", e),
            }
        },
        Error::DetachedTaskStopped,
        ex.clone(),
    );

    info!(target: "fud", "Starting fetch file task");
    let file_task = StoppableTask::new();
    file_task.clone().start(
        tasks::fetch_file_task(fud.clone()),
        |res| async {
            match res {
                Ok(()) | Err(Error::DetachedTaskStopped) => { /* Do nothing */ }
                Err(e) => error!(target: "fud", "Failed starting fetch file task: {}", e),
            }
        },
        Error::DetachedTaskStopped,
        ex.clone(),
    );

    info!(target: "fud", "Starting get task");
    let get_task_ = StoppableTask::new();
    get_task_.clone().start(
        tasks::get_task(fud.clone()),
        |res| async {
            match res {
                Ok(()) | Err(Error::DetachedTaskStopped) => { /* Do nothing */ }
                Err(e) => error!(target: "fud", "Failed starting get task: {}", e),
            }
        },
        Error::DetachedTaskStopped,
        ex.clone(),
    );

    let rpc_settings: RpcSettings = args.rpc.into();
    info!(target: "fud", "Starting JSON-RPC server on {}", rpc_settings.listen);
    let rpc_task = StoppableTask::new();
    let fud_ = fud.clone();
    rpc_task.clone().start(
        listen_and_serve(rpc_settings, fud.clone(), None, ex.clone()),
        |res| async move {
            match res {
                Ok(()) | Err(Error::RpcServerStopped) => fud_.stop_connections().await,
                Err(e) => error!(target: "fud", "Failed starting sync JSON-RPC server: {}", e),
            }
        },
        Error::RpcServerStopped,
        ex.clone(),
    );

    info!("Starting P2P protocols");
    let registry = p2p.protocol_registry();
    let fud_ = fud.clone();
    registry
        .register(SESSION_DEFAULT, move |channel, p2p| {
            let fud_ = fud_.clone();
            async move { ProtocolFud::init(fud_, channel, p2p).await.unwrap() }
        })
        .await;
    p2p.clone().start().await?;

    info!(target: "fud", "Starting DHT tasks");
    let dht_channel_task = StoppableTask::new();
    let fud_ = fud.clone();
    dht_channel_task.clone().start(
        async move { fud_.channel_task::<FudFindNodesReply>().await },
        |res| async {
            match res {
                Ok(()) | Err(Error::DetachedTaskStopped) => { /* Do nothing */ }
                Err(e) => error!(target: "fud", "Failed starting dht channel task: {}", e),
            }
        },
        Error::DetachedTaskStopped,
        ex.clone(),
    );
    let dht_disconnect_task = StoppableTask::new();
    let fud_ = fud.clone();
    dht_disconnect_task.clone().start(
        async move { fud_.disconnect_task().await },
        |res| async {
            match res {
                Ok(()) | Err(Error::DetachedTaskStopped) => { /* Do nothing */ }
                Err(e) => error!(target: "fud", "Failed starting dht disconnect task: {}", e),
            }
        },
        Error::DetachedTaskStopped,
        ex.clone(),
    );
    let prune_task = StoppableTask::new();
    let fud_ = fud.clone();
    prune_task.clone().start(
        async move { tasks::prune_seeders_task(fud_.clone()).await },
        |res| async {
            match res {
                Ok(()) | Err(Error::DetachedTaskStopped) => { /* Do nothing */ }
                Err(e) => error!(target: "fud", "Failed starting prune seeders task: {}", e),
            }
        },
        Error::DetachedTaskStopped,
        ex.clone(),
    );
    let announce_task = StoppableTask::new();
    let fud_ = fud.clone();
    announce_task.clone().start(
        async move { tasks::announce_seed_task(fud_.clone()).await },
        |res| async {
            match res {
                Ok(()) | Err(Error::DetachedTaskStopped) => { /* Do nothing */ }
                Err(e) => error!(target: "fud", "Failed starting announce task: {}", e),
            }
        },
        Error::DetachedTaskStopped,
        ex.clone(),
    );

    // Signal handling for graceful termination.
    let (signals_handler, signals_task) = SignalHandler::new(ex)?;
    signals_handler.wait_termination(signals_task).await?;
    info!("Caught termination signal, cleaning up and exiting...");

    info!(target: "fud", "Stopping fetch file task...");
    file_task.stop().await;

    info!(target: "fud", "Stopping get task...");
    get_task_.stop().await;

    info!(target: "fud", "Stopping JSON-RPC server...");
    rpc_task.stop().await;

    info!(target: "fud", "Stopping P2P network...");
    p2p.stop().await;

    info!(target: "fud", "Stopping DHT tasks");
    dht_channel_task.stop().await;
    dht_disconnect_task.stop().await;
    prune_task.stop().await;
    announce_task.stop().await;

    info!("Bye!");
    Ok(())
}
