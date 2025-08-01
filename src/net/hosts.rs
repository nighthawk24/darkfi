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

use log::{debug, error, info, trace, warn};
use rand::{prelude::IteratorRandom, rngs::OsRng, Rng};
use smol::lock::RwLock as AsyncRwLock;
use std::{
    collections::HashMap,
    fmt, fs,
    fs::File,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as SyncMutex, RwLock,
    },
    time::{Instant, UNIX_EPOCH},
};
use url::{Host, Url};

use super::{
    session::{SESSION_REFINE, SESSION_SEED},
    settings::Settings,
    ChannelPtr,
};
use crate::{
    system::{Publisher, PublisherPtr, Subscription},
    util::{
        file::{load_file, save_file},
        most_frequent_or_any,
        path::expand_path,
        ringbuffer::RingBuffer,
    },
    Error, Result,
};

/// The main interface for interacting with the hostlist. Contains the following:
///
/// `Hosts`: the main parent class that manages HostRegistry and HostContainer. It is also
///  responsible for filtering addresses before writing to the hostlist.
///
/// `HostRegistry`: A locked HashMap that maps peer addresses onto mutually exclusive
///  states (`HostState`). Prevents race conditions by dictating a strict flow of logically
///  acceptable states.
///
/// `HostContainer`: A wrapper for the hostlists. Each hostlist is represented by a `HostColor`,
///  which can be Grey, White, Gold or Black. Exposes a common interface for hostlist queries and
///  utilities.
///
/// `HostColor`:
///     White: Hosts that have passed the `GreylistRefinery` successfully.
///
///     Gold: Hosts we have been able to establish a connection to in `OutboundSession`.
///
///     Grey: Recently received hosts that are checked by the `GreylistRefinery` and
///           upgraded to the whitelist if valid. If they're inaccessible by the Refinery
///           they will be deleted.
///
///     Black: hostile hosts that are strictly avoided for the duration of the program.
///
///     Dark: hosts that do not match our transports, but that we continue to share with
///           other peers. We do not keep darklist entries that are older than one day.
///           This is to avoid peers propagating nodes that may be faulty. We assume that
///           within the one day period, the nodes will be picked up by peers that accept
///           the transports and can refine them to remove inactive peers. Dark list hosts
///           are otherwise ignored.
///
/// `HostState`: a set of mutually exclusive states that can be Insert, Refine, Connect, Suspend
///  or Connected. The state is `None` when the corresponding host has been removed from the
///  HostRegistry.
///
///  TODO: Use HostState::Free `age` variable to implement a pruning logic that deletes peers from
///  the registry once they have bypassed a certain age threshold.
///
// An array containing all possible local host strings
// TODO: This could perhaps be more exhaustive?
pub const LOCAL_HOST_STRS: [&str; 2] = ["localhost", "localhost.localdomain"];
const WHITELIST_MAX_LEN: usize = 5000;
const GREYLIST_MAX_LEN: usize = 2000;
const DARKLIST_MAX_LEN: usize = 1000;

/// Atomic pointer to hosts object
pub type HostsPtr = Arc<Hosts>;

/// Keeps track of hosts and their current state. Prevents race conditions
/// where multiple threads are simultaneously trying to change the state of
/// a given host.
pub(in crate::net) type HostRegistry = SyncMutex<HashMap<Url, HostState>>;

/// HostState is a set of mutually exclusive states that can be Insert,
/// Refine, Move, Connect, Suspend or Connected or Free.
/// ```
///                +------+
///                | free |
///                +------+
///                   ^
///                   |
///                   v
///                +------+      +---------+
///       +------> | move | ---> | suspend |
///       |        +------+      +---------+
///       |           |               |        +--------+
///       |           |               v        | insert |
///  +---------+      |          +--------+    +--------+
///  | connect |      |          | refine |        ^
///  +---------+      |          +--------+        |
///       |           v               |            v
///       |     +-----------+         |         +------+
///       +---> | connected | <-------+-------> | free |
///             +-----------+                   +------+
///                   ^
///                   |
///                   v
///                +------+
///                | free |
///                +------+
///
/// ```
/* NOTE: Currently if a user loses connectivity, they will be deleted from
our hostlist by the refinery process and forgotten about until they regain
connectivity and share their external address with the p2p network again.

We may want to keep nodes with patchy connections in a `Red` list
and periodically try to connect to them in Outbound Session, rather
than sending them to the refinery (which will delete them if they are
offline) as we do using `Suspend`. The current design favors reliability
of connections but this may come at a risk for security since an attacker
is likely to have good uptime. We want to insure that users with patchy
connections or on mobile are still likely to be connected to.*/

#[derive(Clone, Debug)]
pub(in crate::net) enum HostState {
    /// Hosts that are currently being inserting into the hostlist.
    Insert,
    /// Hosts that are migrating from the greylist to the whitelist or being
    /// removed from the greylist, as defined in `refinery.rs`.
    Refine,
    /// Hosts that are being connected to in Outbound and Manual Session.
    Connect,
    /// Hosts that we have just failed to connect to. Marking a host as
    /// Suspend effectively sends this host to refinery, since Suspend->
    /// Refine is an acceptable state transition. Being marked as Suspend does
    /// not increase a host's probability of being refined, since the refinery
    /// selects its subjects randomly (with the caveat that we cannot refine
    /// nodes marked as Connect, Connected, Insert or Move). It does however
    /// mean this host cannot be connected to unless it passes through the
    /// refinery successfully.
    Suspend,
    /// Hosts that have been successfully connected to.
    Connected(ChannelPtr),

    /// Host that are moving between hostlists, implemented in
    /// store::move_host().
    Move,

    /// Free up a peer for any future operation.
    Free(u64),
}

impl HostState {
    // Try to change state to Insert. Only possible if we are not yet
    // tracking this host in the HostRegistry, or if this host is marked
    // as Free.
    fn try_insert(&self) -> Result<Self> {
        let start = self.to_string();
        let end = HostState::Insert.to_string();
        match self {
            HostState::Insert => Err(Error::HostStateBlocked(start, end)),
            HostState::Refine => Err(Error::HostStateBlocked(start, end)),
            HostState::Connect => Err(Error::HostStateBlocked(start, end)),
            HostState::Suspend => Err(Error::HostStateBlocked(start, end)),
            HostState::Connected(_) => Err(Error::HostStateBlocked(start, end)),
            HostState::Move => Err(Error::HostStateBlocked(start, end)),
            HostState::Free(_) => Ok(HostState::Insert),
        }
    }

    // Try to change state to Refine. Only possible if the peer is marked
    // as Free, or Suspend i.e. we have failed to connect to it.
    fn try_refine(&self) -> Result<Self> {
        let start = self.to_string();
        let end = HostState::Refine.to_string();
        match self {
            HostState::Insert => Err(Error::HostStateBlocked(start, end)),
            HostState::Refine => Err(Error::HostStateBlocked(start, end)),
            HostState::Connect => Err(Error::HostStateBlocked(start, end)),
            HostState::Suspend => Ok(HostState::Refine),
            HostState::Connected(_) => Err(Error::HostStateBlocked(start, end)),
            HostState::Move => Err(Error::HostStateBlocked(start, end)),
            HostState::Free(_) => Ok(HostState::Refine),
        }
    }

    // Try to change state to Connect. Only possible if this peer is marked
    // as Free.
    fn try_connect(&self) -> Result<Self> {
        let start = self.to_string();
        let end = HostState::Connect.to_string();
        match self {
            HostState::Insert => Err(Error::HostStateBlocked(start, end)),
            HostState::Refine => Err(Error::HostStateBlocked(start, end)),
            HostState::Connect => Err(Error::HostStateBlocked(start, end)),
            HostState::Suspend => Err(Error::HostStateBlocked(start, end)),
            HostState::Connected(_) => Err(Error::HostStateBlocked(start, end)),
            HostState::Move => Err(Error::HostStateBlocked(start, end)),
            HostState::Free(_) => Ok(HostState::Connect),
        }
    }

    // Try to change state to Connected. Possible if this peer's state
    // is currently Connect, Refine, Move, or Free. Refine is necessary since the
    // refinery process requires us to establish a connection to a peer.
    // Move is necessary due to the upgrade to Gold sequence in
    // `session::perform_handshake_protocols`. Free is necessary since
    // this could be a peer we previously recognize from inbound sessions.
    fn try_connected(&self, channel: ChannelPtr) -> Result<Self> {
        let start = self.to_string();
        let end = HostState::Connected(channel.clone()).to_string();
        match self {
            HostState::Insert => Err(Error::HostStateBlocked(start, end)),
            HostState::Refine => Ok(HostState::Connected(channel)),
            HostState::Connect => Ok(HostState::Connected(channel)),
            HostState::Suspend => Err(Error::HostStateBlocked(start, end)),
            HostState::Connected(_) => Err(Error::HostStateBlocked(start, end)),
            HostState::Move => Ok(HostState::Connected(channel)),
            HostState::Free(_) => Ok(HostState::Connected(channel)),
        }
    }

    // Try to change state to Move. Possibly if this host is currently
    // Connect i.e. it is being connected to, if we are currently Connected
    // to this peer (due to host Downgrade sequence in `session::remove_sub_on_stop`),
    // or if this node is Free (since we might recognize this peer from a previous
    // inbound session).
    fn try_move(&self) -> Result<Self> {
        let start = self.to_string();
        let end = HostState::Move.to_string();
        match self {
            HostState::Insert => Err(Error::HostStateBlocked(start, end)),
            HostState::Refine => Ok(HostState::Move),
            HostState::Connect => Ok(HostState::Move),
            HostState::Suspend => Err(Error::HostStateBlocked(start, end)),
            HostState::Connected(_) => Ok(HostState::Move),
            HostState::Move => Err(Error::HostStateBlocked(start, end)),
            HostState::Free(_) => Ok(HostState::Move),
        }
    }

    // Try to change the state to Suspend. Only possible when we are
    // currently moving this host, since we suspend a host after failing
    // to connect to it in `outbound_session::try_connect` and then downgrading
    // in `hosts::move_host`.
    fn try_suspend(&self) -> Result<Self> {
        let start = self.to_string();
        let end = HostState::Suspend.to_string();
        match self {
            HostState::Insert => Err(Error::HostStateBlocked(start, end)),
            HostState::Refine => Err(Error::HostStateBlocked(start, end)),
            HostState::Connect => Err(Error::HostStateBlocked(start, end)),
            HostState::Suspend => Err(Error::HostStateBlocked(start, end)),
            HostState::Connected(_) => Err(Error::HostStateBlocked(start, end)),
            HostState::Move => Ok(HostState::Suspend),
            HostState::Free(_) => Err(Error::HostStateBlocked(start, end)),
        }
    }

    // Free up this host to be used by the HostRegistry. The most permissive
    // state that allows every state transition.
    // This is preferable to simply deleting hosts from the HostRegistry since
    // it is less likely to result in race conditions.
    fn try_free(&self, age: u64) -> Result<Self> {
        match self {
            HostState::Insert => Ok(HostState::Free(age)),
            HostState::Refine => Ok(HostState::Free(age)),
            HostState::Connect => Ok(HostState::Free(age)),
            HostState::Suspend => Ok(HostState::Free(age)),
            HostState::Connected(_) => Ok(HostState::Free(age)),
            HostState::Move => Ok(HostState::Free(age)),
            HostState::Free(age) => Ok(HostState::Free(*age)),
        }
    }
}

impl fmt::Display for HostState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum HostColor {
    /// Intermediary nodes that are periodically probed and updated
    /// to White.
    Grey = 0,
    /// Recently seen hosts. Shared with other nodes.
    White = 1,
    /// Nodes to which we have already been able to establish a
    /// connection.
    Gold = 2,
    /// Hostile peers that can neither be connected to nor establish
    /// connections to us for the duration of the program.
    Black = 3,
    /// Peers that do not match our accepted transports. We are blind
    /// to these nodes (we do not use them) but we send them around
    /// the network anyway to ensure all transports are propagated.
    /// Cleared once daily.
    Dark = 4,
}

impl TryFrom<usize> for HostColor {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self> {
        match value {
            0 => Ok(HostColor::Grey),
            1 => Ok(HostColor::White),
            2 => Ok(HostColor::Gold),
            3 => Ok(HostColor::Black),
            4 => Ok(HostColor::Dark),
            _ => Err(Error::InvalidHostColor),
        }
    }
}

/// A Container for managing Grey, White, Gold and Black hostlists. Exposes
/// a common interface for writing to and querying hostlists.
// TODO: Benchmark hostlist operations when the hostlist is at max size.
pub struct HostContainer {
    pub(in crate::net) hostlists: [RwLock<Vec<(Url, u64)>>; 5],
}

impl HostContainer {
    fn new() -> Self {
        let hostlists: [RwLock<Vec<(Url, u64)>>; 5] = [
            RwLock::new(Vec::new()),
            RwLock::new(Vec::new()),
            RwLock::new(Vec::new()),
            RwLock::new(Vec::new()),
            RwLock::new(Vec::new()),
        ];

        Self { hostlists }
    }

    /// Append host to a hostlist. Called when initalizing the hostlist in load_hosts().
    fn store(&self, color: usize, addr: Url, last_seen: u64) {
        trace!(target: "net::hosts::store()", "[START] list={:?}",
        HostColor::try_from(color).unwrap());

        let mut list = self.hostlists[color].write().unwrap();
        list.push((addr.clone(), last_seen));
        debug!(target: "net::hosts::store()", "Added [{addr}] to {:?} list",
               HostColor::try_from(color).unwrap());

        trace!(target: "net::hosts::store()", "[END] list={:?}",
               HostColor::try_from(color).unwrap());
    }

    /// Stores an address on a hostlist or updates its last_seen field if
    /// we already have the address.
    fn store_or_update(&self, color: HostColor, addr: Url, last_seen: u64) {
        trace!(target: "net::hosts::store_or_update()", "[START]");
        let color_code = color.clone() as usize;
        let mut list = self.hostlists[color_code].write().unwrap();
        if let Some(entry) = list.iter_mut().find(|(u, _)| *u == addr) {
            entry.1 = last_seen;
            debug!(target: "net::hosts::store_or_update()", "Updated [{addr}] entry on {:?} list",
                color.clone());
        } else {
            list.push((addr.clone(), last_seen));
            debug!(target: "net::hosts::store_or_update()", "Added [{addr}] to {color:?} list");
        }
        trace!(target: "net::hosts::store_or_update()", "[STOP]");
    }

    /// Update the last_seen field of a peer on a hostlist.
    pub fn update_last_seen(&self, color: usize, addr: Url, last_seen: u64) {
        trace!(target: "net::hosts::update_last_seen()", "[START] list={:?}",
        HostColor::try_from(color).unwrap());

        let mut list = self.hostlists[color].write().unwrap();
        if let Some(entry) = list.iter_mut().find(|(u, _)| *u == addr) {
            entry.1 = last_seen;
        }
        trace!(target: "net::hosts::update_last_seen()", "[END] list={:?}",
               HostColor::try_from(color).unwrap());
    }

    /// Return all known hosts on a hostlist.
    pub fn fetch_all(&self, color: HostColor) -> Vec<(Url, u64)> {
        self.hostlists[color as usize].read().unwrap().iter().cloned().collect()
    }

    /// Get the oldest entry from a hostlist.
    pub fn fetch_last(&self, color: HostColor) -> Option<(Url, u64)> {
        let list = self.hostlists[color as usize].read().unwrap();
        list.last().cloned()
    }

    /// Fetch addresses that match the provided transports or acceptable
    /// mixed transports.  Will return an empty Vector if no such addresses
    /// were found.
    pub(in crate::net) fn fetch(
        &self,
        color: HostColor,
        transports: &[String],
        mixed_transports: &[String],
        tor_socks5_proxy: Option<Url>,
        nym_socks5_proxy: Option<Url>,
    ) -> Vec<(Url, u64)> {
        trace!(target: "net::hosts::fetch_addrs()", "[START] {color:?}");
        let mut hosts = vec![];
        let index = color as usize;

        // If transport mixing is enabled, then for example we're allowed to
        // use tor:// to connect to tcp:// and tor+tls:// to connect to tcp+tls://.
        // However, **do not** mix tor:// and tcp+tls://, nor tor+tls:// and tcp://.
        macro_rules! mix_transport {
            ($a:expr, $b:expr) => {
                if transports.contains(&$a.to_string()) &&
                    mixed_transports.contains(&$b.to_string())
                {
                    let mut a_to_b = self.fetch_with_schemes(index, &[$b.to_string()], None);
                    for (addr, last_seen) in a_to_b.iter_mut() {
                        addr.set_scheme($a).unwrap();
                        hosts.push((addr.clone(), last_seen.clone()));
                    }
                }
            };
        }

        macro_rules! mix_socks5_transport {
            ($a:expr, $b:expr, $proxies:expr) => {
                if transports.contains(&$a.to_string()) &&
                    mixed_transports.contains(&$b.to_string())
                {
                    let mut a_to_b = self.fetch_with_schemes(index, &[$b.to_string()], None);
                    for (addr, last_seen) in a_to_b.iter_mut() {
                        for proxy in $proxies {
                            if let Some(mut endpoint) = proxy {
                                endpoint.set_path(&format!(
                                    "{}:{}",
                                    addr.host().unwrap(),
                                    addr.port().unwrap()
                                ));
                                endpoint.set_scheme($a).unwrap();
                                hosts.push((endpoint, last_seen.clone()));
                            }
                        }
                    }
                }
            };
        }

        mix_transport!("tor", "tcp");
        mix_transport!("tor+tls", "tcp+tls");
        mix_transport!("nym", "tcp");
        mix_transport!("nym+tls", "tcp+tls");
        mix_socks5_transport!(
            "socks5",
            "tcp",
            [tor_socks5_proxy.clone(), nym_socks5_proxy.clone()]
        );
        mix_socks5_transport!(
            "socks5+tls",
            "tcp+tls",
            [tor_socks5_proxy.clone(), nym_socks5_proxy.clone()]
        );
        mix_socks5_transport!("socks5", "tor", [tor_socks5_proxy.clone()]);
        mix_socks5_transport!("socks5+tls", "tor+tls", [tor_socks5_proxy.clone()]);

        // Filter out a transport from requested transport if we set it to be mixed as
        // we don't want to connect directly to that host
        let transports: Vec<String> =
            transports.iter().filter(|tp| !mixed_transports.contains(tp)).cloned().collect();

        // And now the actual requested transports
        for (addr, last_seen) in self.fetch_with_schemes(index, &transports, None) {
            hosts.push((addr, last_seen));
        }

        trace!(target: "net::hosts::fetch_addrs()", "Grabbed hosts, length: {}", hosts.len());

        hosts
    }

    /// Get up to limit peers that match the given transport schemes from
    /// a hostlist.  If limit was not provided, return all matching peers.
    fn fetch_with_schemes(
        &self,
        color: usize,
        schemes: &[String],
        limit: Option<usize>,
    ) -> Vec<(Url, u64)> {
        trace!(target: "net::hosts::fetch_with_schemes()", "[START] {:?}",
               HostColor::try_from(color).unwrap());

        let list = self.hostlists[color].read().unwrap();

        let mut limit = match limit {
            Some(l) => l.min(list.len()),
            None => list.len(),
        };
        let mut ret = vec![];

        if limit == 0 {
            return ret
        }

        for (addr, last_seen) in list.iter() {
            if schemes.contains(&addr.scheme().to_string()) {
                ret.push((addr.clone(), *last_seen));
                limit -= 1;
                if limit == 0 {
                    debug!(target: "net::hosts::fetch_with_schemes()",
                           "Found matching addr on list={:?}, returning {} addresses",
                           HostColor::try_from(color).unwrap(), ret.len());
                    return ret
                }
            }
        }

        if ret.is_empty() {
            debug!(target: "net::hosts::fetch_with_schemes()",
                   "No matching schemes found on list={:?}!", HostColor::try_from(color).unwrap())
        }

        ret
    }

    /// Get up to limit peers that don't match the given transport schemes
    /// from a hostlist.  If limit was not provided, return all matching
    /// peers.
    fn fetch_excluding_schemes(
        &self,
        color: usize,
        schemes: &[String],
        limit: Option<usize>,
    ) -> Vec<(Url, u64)> {
        trace!(target: "net::hosts::fetch_with_schemes()", "[START] {:?}",
               HostColor::try_from(color).unwrap());

        let list = self.hostlists[color].read().unwrap();

        let mut limit = match limit {
            Some(l) => l.min(list.len()),
            None => list.len(),
        };
        let mut ret = vec![];

        if limit == 0 {
            return ret
        }

        for (addr, last_seen) in list.iter() {
            if !schemes.contains(&addr.scheme().to_string()) {
                ret.push((addr.clone(), *last_seen));
                limit -= 1;
                if limit == 0 {
                    return ret
                }
            }
        }

        if ret.is_empty() {
            debug!(target: "net::hosts::fetch_excluding_schemes()", "No such schemes found!");
        }

        ret
    }

    /// Get a random peer from a hostlist that matches the given transport
    /// schemes.
    pub(in crate::net) fn fetch_random_with_schemes(
        &self,
        color: HostColor,
        schemes: &[String],
    ) -> Option<((Url, u64), usize)> {
        // Retrieve all peers corresponding to that transport schemes
        trace!(target: "net::hosts::fetch_random_with_schemes()", "[START] {color:?}");
        let list = self.fetch_with_schemes(color as usize, schemes, None);

        if list.is_empty() {
            return None
        }

        let position = rand::thread_rng().gen_range(0..list.len());
        let entry = &list[position];
        Some((entry.clone(), position))
    }

    /// Get up to n random peers. Schemes are not taken into account.
    pub(in crate::net) fn fetch_n_random(&self, color: HostColor, n: u32) -> Vec<(Url, u64)> {
        trace!(target: "net::hosts::fetch_n_random()", "[START] {color:?}");
        let n = n as usize;
        if n == 0 {
            return vec![]
        }
        let mut hosts = vec![];

        let list = self.hostlists[color as usize].read().unwrap();

        for (addr, last_seen) in list.iter() {
            hosts.push((addr.clone(), *last_seen));
        }

        if hosts.is_empty() {
            debug!(target: "net::hosts::fetch_n_random()", "No entries found!");
            return hosts
        }

        // Grab random ones
        let urls = hosts.iter().choose_multiple(&mut OsRng, n.min(hosts.len()));
        urls.iter().map(|&url| url.clone()).collect()
    }

    /// Get up to n random peers that match the given transport schemes.
    pub(in crate::net) fn fetch_n_random_with_schemes(
        &self,
        color: HostColor,
        schemes: &[String],
        n: u32,
    ) -> Vec<(Url, u64)> {
        trace!(target: "net::hosts::fetch_n_random_with_schemes()", "[START] {color:?}");
        let index = color as usize;
        let n = n as usize;
        if n == 0 {
            return vec![]
        }

        // Retrieve all peers corresponding to that transport schemes
        let hosts = self.fetch_with_schemes(index, schemes, None);
        if hosts.is_empty() {
            debug!(target: "net::hosts::fetch_n_random_with_schemes()",
                  "No such schemes found!");
            return hosts
        }

        // Grab random ones
        let urls = hosts.iter().choose_multiple(&mut OsRng, n.min(hosts.len()));
        urls.iter().map(|&url| url.clone()).collect()
    }

    /// Get up to n random peers that don't match the given transport schemes
    /// from a hostlist.
    pub(in crate::net) fn fetch_n_random_excluding_schemes(
        &self,
        color: HostColor,
        schemes: &[String],
        n: u32,
    ) -> Vec<(Url, u64)> {
        trace!(target: "net::hosts::fetch_excluding_schemes()", "[START] {color:?}");
        let index = color as usize;
        let n = n as usize;
        if n == 0 {
            return vec![]
        }
        // Retrieve all peers not corresponding to that transport schemes
        let hosts = self.fetch_excluding_schemes(index, schemes, None);

        if hosts.is_empty() {
            debug!(target: "net::hosts::fetch_n_random_excluding_schemes()",
            "No such schemes found!");
            return hosts
        }

        // Grab random ones
        let urls = hosts.iter().choose_multiple(&mut OsRng, n.min(hosts.len()));
        urls.iter().map(|&url| url.clone()).collect()
    }

    /// Remove an entry from a hostlist if it exists.
    pub fn remove_if_exists(&self, color: HostColor, addr: &Url) {
        let color_code = color.clone() as usize;
        let mut list = self.hostlists[color_code].write().unwrap();
        if let Some(position) = list.iter().position(|(u, _)| u == addr) {
            debug!(target: "net::hosts::remove_if_exists()", "Removing addr={addr} list={color:?}");
            list.remove(position);
        }
    }

    /// Check if a hostlist is empty.
    pub fn is_empty(&self, color: HostColor) -> bool {
        self.hostlists[color as usize].read().unwrap().is_empty()
    }

    /// Check if host is in a hostlist
    pub fn contains(&self, color: usize, addr: &Url) -> bool {
        self.hostlists[color].read().unwrap().iter().any(|(u, _t)| u == addr)
    }

    /// Get the index for a given addr on a hostlist.
    pub fn get_index_at_addr(&self, color: usize, addr: Url) -> Option<usize> {
        self.hostlists[color].read().unwrap().iter().position(|a| a.0 == addr)
    }

    /// Get the last_seen field for a given entry on a hostlist.
    pub fn get_last_seen(&self, color: usize, addr: &Url) -> Option<u64> {
        self.hostlists[color]
            .read()
            .unwrap()
            .iter()
            .find(|(url, _)| url == addr)
            .map(|(_, last_seen)| *last_seen)
    }

    /// Sort a hostlist by last_seen.
    fn sort_by_last_seen(&self, color: usize) {
        let mut list = self.hostlists[color].write().unwrap();
        list.sort_by_key(|entry| entry.1);
        list.reverse();
    }

    /// Remove the last item on a hostlist if it reaches max size.
    fn resize(&self, color: HostColor) {
        let list = self.hostlists[color.clone() as usize].read().unwrap();
        let size = list.len();

        // Immediately drop the read lock.
        drop(list);

        match color {
            HostColor::Grey | HostColor::White | HostColor::Dark => {
                let max_size = match color {
                    HostColor::Grey => GREYLIST_MAX_LEN,
                    HostColor::White => WHITELIST_MAX_LEN,
                    HostColor::Dark => DARKLIST_MAX_LEN,
                    _ => {
                        unreachable!()
                    }
                };
                if size == max_size {
                    let mut list = self.hostlists[color.clone() as usize].write().unwrap();
                    let last_entry = list.pop().unwrap();

                    debug!(
                        target: "net::hosts::resize()",
                        "{color:?}list reached max size. Removed {last_entry:?}"
                    );
                }
            }
            // Gold and Black list do not have a max size.
            HostColor::Gold | HostColor::Black => (),
        }
    }

    /// Delete items from a hostlist that are older than a specified maximum.
    /// Maximum should be specified in seconds.
    fn refresh(&self, color: HostColor, max_age: u64) {
        let now = UNIX_EPOCH.elapsed().unwrap().as_secs();
        let mut old_items = vec![];

        let darklist = self.fetch_all(HostColor::Dark);
        for (addr, last_seen) in darklist {
            // Skip if last_seen comes from the future.
            //
            // We do this to avoid an overflow, which can happen if
            // our system clock is behind or if other nodes are
            // misreporting the last_seen field.
            if now < last_seen {
                debug!(target: "net::hosts::refresh()",
                "last_seen [{now}] is newer than current system time [{last_seen}]. Skipping");
                continue
            }
            if (now - last_seen) > max_age {
                old_items.push(addr);
            }
        }

        for item in old_items {
            debug!(target: "net::hosts::refresh()", "Removing {item:?}");
            self.remove_if_exists(color.clone(), &item);
        }
    }

    /// Load the hostlists from a file.
    pub(in crate::net) fn load_all(&self, path: &str) -> Result<()> {
        let path = expand_path(path)?;

        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }

            File::create(path.clone())?;
        }

        let contents = load_file(&path);
        if let Err(e) = contents {
            warn!(target: "net::hosts::load_hosts()", "Failed retrieving saved hosts: {e}");
            return Ok(())
        }

        for line in contents.unwrap().lines() {
            let data: Vec<&str> = line.split('\t').collect();

            let url = match Url::parse(data[1]) {
                Ok(u) => u,
                Err(e) => {
                    debug!(target: "net::hosts::load_hosts()", "Skipping malformed URL {e}");
                    continue
                }
            };

            let last_seen = match data[2].parse::<u64>() {
                Ok(t) => t,
                Err(e) => {
                    debug!(target: "net::hosts::load_hosts()", "Skipping malformed last seen {e}");
                    continue
                }
            };

            match data[0] {
                "gold" => {
                    self.store(HostColor::Gold as usize, url, last_seen);
                    self.sort_by_last_seen(HostColor::Gold as usize);
                }
                "white" => {
                    self.store(HostColor::White as usize, url, last_seen);
                    self.sort_by_last_seen(HostColor::White as usize);
                    self.resize(HostColor::White);
                }
                "grey" => {
                    self.store(HostColor::Grey as usize, url, last_seen);
                    self.sort_by_last_seen(HostColor::Grey as usize);
                    self.resize(HostColor::Grey);
                }
                "dark" => {
                    self.store(HostColor::Dark as usize, url, last_seen);
                    self.sort_by_last_seen(HostColor::Dark as usize);
                    self.resize(HostColor::Dark);

                    // Delete darklist entries that are older than one day.
                    let day = 86400;
                    self.refresh(HostColor::Dark, day);
                }
                _ => {
                    debug!(target: "net::hosts::load_hosts()", "Malformed list name...");
                }
            }
        }

        Ok(())
    }

    /// Save the hostlist to a file.
    pub(in crate::net) fn save_all(&self, path: &str) -> Result<()> {
        let path = expand_path(path)?;

        let mut tsv = String::new();
        let mut hostlist: HashMap<String, Vec<(Url, u64)>> = HashMap::new();

        hostlist.insert("dark".to_string(), self.fetch_all(HostColor::Dark));
        hostlist.insert("grey".to_string(), self.fetch_all(HostColor::Grey));
        hostlist.insert("white".to_string(), self.fetch_all(HostColor::White));
        hostlist.insert("gold".to_string(), self.fetch_all(HostColor::Gold));

        for (name, list) in hostlist {
            for (url, last_seen) in list {
                tsv.push_str(&format!("{name}\t{url}\t{last_seen}\n"));
            }
        }

        if !tsv.is_empty() {
            info!(target: "net::hosts::save_hosts()", "Saving hosts to: {path:?}");
            if let Err(e) = save_file(&path, &tsv) {
                error!(target: "net::hosts::save_hosts()", "Failed saving hosts: {e}");
            }
        }

        Ok(())
    }
}

/// Main parent class for the management and manipulation of
/// hostlists.
///
/// Keeps track of hosts and their current state via the HostRegistry,
/// and stores hostlists and associated methods in the HostContainer.
/// Also operates two publishers to notify other parts of the code base
/// when new channels have been created or new hosts have been added to
/// the hostlist.
pub struct Hosts {
    /// A registry that tracks hosts and their current state.
    registry: HostRegistry,

    /// Hostlists and associated methods.
    pub container: HostContainer,

    /// Publisher listening for store updates
    store_publisher: PublisherPtr<usize>,

    /// Publisher for notifications of new channels
    pub(in crate::net) channel_publisher: PublisherPtr<Result<ChannelPtr>>,

    /// Publisher listening for network disconnects
    pub(in crate::net) disconnect_publisher: PublisherPtr<Error>,

    /// Keeps track of the last time a connection was made.
    pub(in crate::net) last_connection: SyncMutex<Instant>,

    /// Marker for IPv6 availability
    pub(in crate::net) ipv6_available: AtomicBool,

    /// Auto self discovered addresses. Used for filtering self connections.
    auto_self_addrs: SyncMutex<RingBuffer<Ipv6Addr, 20>>,

    /// Pointer to configured P2P settings
    settings: Arc<AsyncRwLock<Settings>>,
}

impl Hosts {
    /// Create a new hosts list
    pub(in crate::net) fn new(settings: Arc<AsyncRwLock<Settings>>) -> HostsPtr {
        Arc::new(Self {
            registry: SyncMutex::new(HashMap::new()),
            container: HostContainer::new(),
            store_publisher: Publisher::new(),
            channel_publisher: Publisher::new(),
            disconnect_publisher: Publisher::new(),
            last_connection: SyncMutex::new(Instant::now()),
            ipv6_available: AtomicBool::new(true),
            auto_self_addrs: SyncMutex::new(RingBuffer::new()),
            settings,
        })
    }

    /// Safely insert into the HostContainer. Filters the addresses first before storing and
    /// notifies the publisher. Must be called when first receiving greylist addresses.
    pub(in crate::net) async fn insert(&self, color: HostColor, addrs: &[(Url, u64)]) {
        trace!(target: "net::hosts:insert()", "[START]");

        // First filter these address to ensure this peer doesn't exist in our black, gold or
        // whitelist and apply transport filtering. If we don't support this transport,
        // store the peer on our dark list to broadcast to other nodes.
        let filtered_addrs = self.filter_addresses(addrs).await;
        let mut addrs_len = 0;

        if filtered_addrs.is_empty() {
            debug!(target: "net::hosts::insert()", "Filtered out all addresses");
        }

        // Then ensure we aren't currently trying to add this peer to the hostlist.
        for (i, (addr, last_seen)) in filtered_addrs.iter().enumerate() {
            if let Err(e) = self.try_register(addr.clone(), HostState::Insert) {
                debug!(target: "net::hosts::store_or_update", "Cannot insert addr={}, err={e}",
                       addr.clone());

                continue
            }

            addrs_len += i + 1;

            self.container.store_or_update(color.clone(), addr.clone(), *last_seen);
            self.container.sort_by_last_seen(color.clone() as usize);
            self.container.resize(color.clone());

            self.unregister(addr);
        }

        self.store_publisher.notify(addrs_len).await;
        trace!(target: "net::hosts:insert()", "[END]");
    }

    /// Check whether a peer is available to be refined currently. Returns true
    /// if available, false otherwise.
    pub fn refinable(&self, addr: Url) -> bool {
        self.try_register(addr.clone(), HostState::Refine).is_ok()
    }

    /// Try to update the registry. If the host already exists, try to update its state.
    /// Otherwise add the host to the registry along with its state.
    pub(in crate::net) fn try_register(
        &self,
        addr: Url,
        new_state: HostState,
    ) -> Result<HostState> {
        let mut registry = self.registry.lock().unwrap();

        trace!(target: "net::hosts::try_update_registry()", "Try register addr={addr}, state={}",
               &new_state);

        if registry.contains_key(&addr) {
            let current_state = registry.get(&addr).unwrap().clone();

            let result: Result<HostState> = match new_state {
                HostState::Insert => current_state.try_insert(),
                HostState::Refine => current_state.try_refine(),
                HostState::Connect => current_state.try_connect(),
                HostState::Suspend => current_state.try_suspend(),
                HostState::Connected(c) => current_state.try_connected(c),
                HostState::Move => current_state.try_move(),
                HostState::Free(a) => current_state.try_free(a),
            };

            if let Ok(state) = &result {
                registry.insert(addr.clone(), state.clone());
            }

            trace!(target: "net::hosts::try_update_registry()", "Returning result {result:?}");

            result
        } else {
            // We don't know this peer. We can safely update the state.
            debug!(target: "net::hosts::try_update_registry()", "Inserting addr={addr}, state={}",
                   &new_state);

            registry.insert(addr.clone(), new_state.clone());

            Ok(new_state)
        }
    }

    // Loop through hosts selected by Outbound Session and see if any of them are
    // free to connect to.
    pub(in crate::net) async fn check_addrs(&self, hosts: Vec<(Url, u64)>) -> Option<(Url, u64)> {
        trace!(target: "net::hosts::check_addrs()", "[START]");

        let seeds = self.settings.read().await.seeds.clone();
        let external_addrs = self.external_addrs().await;

        for (host, last_seen) in hosts {
            // Print a warning if we are trying to connect to a seed node in
            // Outbound session. This shouldn't happen as we reject configured
            // seed nodes from entering our hostlist in filter_addrs().
            if seeds.contains(&host) {
                warn!(
                    target: "net::hosts::check_addrs",
                    "Seed addr={} has entered the hostlist! Skipping", host.clone(),
                );
                continue
            }

            if external_addrs.contains(&host) {
                warn!(
                    target: "net::hosts::check_addrs",
                    "External addr={} has entered the hostlist! Skipping", host.clone(),
                );
                continue
            }

            if let Err(e) = self.try_register(host.clone(), HostState::Connect) {
                trace!(
                    target: "net::hosts::check_addrs",
                    "Skipping addr={}, err={e}", host.clone(),
                );
                continue
            }

            debug!(target: "net::hosts::check_addrs()", "Found valid host {host}");
            return Some((host.clone(), last_seen))
        }

        None
    }

    /// Mark as host as Free which frees it up for most future operations.
    pub(in crate::net) fn unregister(&self, addr: &Url) {
        let age = UNIX_EPOCH.elapsed().unwrap().as_secs();
        self.try_register(addr.clone(), HostState::Free(age)).unwrap();
        debug!(target: "net::hosts::unregister()", "Unregistered: {}", &addr);
    }

    /// Return the list of all connected channels, including seed and
    /// refinery connections.
    pub fn channels(&self) -> Vec<ChannelPtr> {
        let registry = self.registry.lock().unwrap();
        let mut channels = Vec::new();

        for (_, state) in registry.iter() {
            if let HostState::Connected(c) = state {
                channels.push(c.clone());
            }
        }
        channels
    }

    /// Grab the channel pointer of provided channel ID, if it exists.
    pub fn get_channel(&self, id: u32) -> Option<ChannelPtr> {
        let mut channel = None;

        let channels = self.channels();
        for c in channels {
            if c.info.id == id {
                channel = Some(c.clone());
                break
            }
        }

        channel
    }

    /// Return the list of connected peers. Seed and refinery connections
    /// are not taken into account.
    pub fn peers(&self) -> Vec<ChannelPtr> {
        let registry = self.registry.lock().unwrap();
        let mut channels = Vec::new();

        for (_, state) in registry.iter() {
            if let HostState::Connected(c) = state {
                // Skip this channel is it's a seed or refine session.
                if c.session_type_id() & (SESSION_SEED | SESSION_REFINE) != 0 {
                    continue
                }
                channels.push(c.clone());
            }
        }
        channels
    }

    /// Returns the list of suspended channels.
    pub(in crate::net) fn suspended(&self) -> Vec<Url> {
        let registry = self.registry.lock().unwrap();
        let mut addrs = Vec::new();

        for (url, state) in registry.iter() {
            if let HostState::Suspend = state {
                addrs.push(url.clone());
            }
        }
        addrs
    }

    /// Retrieve a random connected channel
    pub fn random_channel(&self) -> ChannelPtr {
        let channels = self.channels();
        let position = rand::thread_rng().gen_range(0..channels.len());
        channels[position].clone()
    }

    /// Add a channel to the set of connected channels
    pub(in crate::net) async fn register_channel(&self, channel: ChannelPtr) {
        let address = channel.address().clone();

        // This is an attempt to skip any Tor (and similar-behaving) inbound connections
        if channel.p2p().settings().read().await.inbound_addrs.contains(&address) {
            return
        }

        // This will error if we are already connected to this peer, this peer
        // is suspended, or this peer is currently being inserted into the hostlist.
        // None of these scenarios should ever happen.
        if let Err(e) = self.try_register(address.clone(), HostState::Connected(channel.clone())) {
            warn!(target: "net::hosts::register_channel", "Error while registering channel {channel:?}: {e:?}");
            return
        }

        // Notify that channel processing was successful
        self.channel_publisher.notify(Ok(channel.clone())).await;

        let mut last_online = self.last_connection.lock().unwrap();
        *last_online = Instant::now();
    }

    /// Get notified when new hosts have been inserted into a hostlist.
    pub async fn subscribe_store(&self) -> Subscription<usize> {
        self.store_publisher.clone().subscribe().await
    }

    /// Get notified when a new channel has been created
    pub async fn subscribe_channel(&self) -> Subscription<Result<ChannelPtr>> {
        self.channel_publisher.clone().subscribe().await
    }

    /// Get notified when a node has no active connections (is disconnected)
    pub async fn subscribe_disconnect(&self) -> Subscription<Error> {
        self.disconnect_publisher.clone().subscribe().await
    }

    // Verify whether a URL is local.
    // NOTE: This function is stateless and not specific to
    // `Hosts`. For this reason, it might make more sense
    // to move this function to a more appropriate location
    // in the codebase.
    /// Check whether a URL is local host
    pub fn is_local_host(&self, url: &Url) -> bool {
        // Reject Urls without host strings.
        if url.host_str().is_none() {
            return false
        }

        // Filter private IP ranges
        match url.host().unwrap() {
            url::Host::Ipv4(ip) => {
                if !ip.unstable_is_global() {
                    return true
                }
            }
            url::Host::Ipv6(ip) => {
                if !ip.unstable_is_global() {
                    return true
                }
            }
            url::Host::Domain(d) => {
                if LOCAL_HOST_STRS.contains(&d) {
                    return true
                }
            }
        }
        false
    }

    /// Check whether a URL is IPV6
    pub fn is_ipv6(&self, url: &Url) -> bool {
        // Reject Urls without host strings.
        if url.host_str().is_none() {
            return false
        }

        if let url::Host::Ipv6(_) = url.host().unwrap() {
            return true
        }
        false
    }

    /// Import blacklisted peers specified in the config file.
    pub(in crate::net) async fn import_blacklist(&self) -> Result<()> {
        for (hostname, schemes, ports) in self.settings.read().await.blacklist.clone() {
            // If schemes are not set use default tcp+tls.
            let schemes = if schemes.is_empty() { vec!["tcp+tls".to_string()] } else { schemes };

            // If ports are not set block all ports.
            let ports = if ports.is_empty() { vec![0] } else { ports };

            for scheme in schemes {
                for &port in &ports {
                    let url_string = if port == 0 {
                        format!("{scheme}://{hostname}")
                    } else {
                        format!("{scheme}://{hostname}:{port}")
                    };

                    if let Ok(url) = Url::parse(&url_string) {
                        self.container.store(HostColor::Black as usize, url, 0);
                    }
                }
            }
        }
        Ok(())
    }

    /// To block a peer trying to access by all ports, simply store its
    /// hostname in the blacklist. This method will check if a host is
    /// stored in the blacklist without a port, and if so, it will return
    /// true.
    pub(in crate::net) fn block_all_ports(&self, url: &Url) -> bool {
        let host = url.host();
        if host.is_none() {
            // the url is a unix socket or an invalid address so it won't be in hostlist
            return false
        }

        let host = host.unwrap();
        self.container.hostlists[HostColor::Black as usize]
            .read()
            .unwrap()
            .iter()
            .any(|(u, _t)| u.host().unwrap() == host && u.port().is_none())
    }

    /// Filter given addresses based on certain rulesets and validity. Strictly called only on
    /// the first time learning of new peers.
    async fn filter_addresses(&self, addrs: &[(Url, u64)]) -> Vec<(Url, u64)> {
        debug!(target: "net::hosts::filter_addresses", "Filtering addrs: {addrs:?}");
        let mut ret = vec![];

        // Acquire read lock on P2P settings. Dropped when this function finishes.
        let settings = self.settings.read().await;

        'addr_loop: for (addr_, last_seen) in addrs {
            // Validate that the format is `scheme://host_str:port`
            if addr_.host_str().is_none() || addr_.port().is_none() || addr_.cannot_be_a_base() {
                debug!(
                    target: "net::hosts::filter_addresses",
                    "[{addr_}] has invalid addr format. Skipping"
                );
                continue
            }

            // Configured seeds should never enter the hostlist.
            if settings.seeds.contains(addr_) {
                debug!(
                    target: "net::hosts::filter_addresses",
                    "[{addr_}] is a configured seed. Skipping"
                );
                continue
            }

            // Configured peers should not enter the hostlist.
            if settings.peers.contains(addr_) {
                debug!(
                    target: "net::hosts::filter_addresses",
                    "[{addr_}] is a configured peer. Skipping"
                );
                continue
            }

            // Blacklist peers should never enter the hostlist.
            if self.container.contains(HostColor::Black as usize, addr_) ||
                self.block_all_ports(addr_)
            {
                debug!(
                    target: "net::hosts::filter_addresses",
                    "[{addr_}] is blacklisted"
                );
                continue
            }

            let host = addr_.host().unwrap();
            let host_str = addr_.host_str().unwrap();

            if !settings.localnet {
                // Our own external addresses should never enter the hosts set.
                for ext in self.external_addrs().await {
                    if host == ext.host().unwrap() {
                        debug!(
                            target: "net::hosts::filter_addresses",
                            "[{addr_}] is our own external addr. Skipping"
                        );
                        continue 'addr_loop
                    }
                }
            } else {
                // On localnet, make sure ours ports don't enter the host set.
                for ext in &settings.external_addrs {
                    if addr_.port() == ext.port() {
                        debug!(
                            target: "net::hosts::filter_addresses",
                            "[{addr_}] is our own localnet port. Skipping"
                        );
                        continue 'addr_loop
                    }
                }
            }

            // Filter non-global ranges if we're not allowing localnet.
            // Should never be allowed in production, so we don't really care
            // about some of them (e.g. 0.0.0.0, or broadcast, etc.).
            if !settings.localnet && self.is_local_host(addr_) {
                debug!(
                    target: "net::hosts::filter_addresses",
                    "[{addr_}] Filtering non-global ranges"
                );
                continue
            }

            match addr_.scheme() {
                // Validate that the address is an actual onion.
                #[cfg(feature = "p2p-tor")]
                "tor" | "tor+tls" => {
                    use std::str::FromStr;
                    if tor_hscrypto::pk::HsId::from_str(host_str).is_err() {
                        continue
                    }
                    trace!(
                        target: "net::hosts::filter_addresses",
                        "[Tor] Valid: {host_str}"
                    );
                }

                #[cfg(feature = "p2p-nym")]
                "nym" | "nym+tls" => continue, // <-- Temp skip

                "tcp" | "tcp+tls" => {
                    trace!(
                        target: "net::hosts::filter_addresses",
                        "[TCP] Valid: {host_str}"
                    );
                }

                #[cfg(feature = "p2p-i2p")]
                "i2p" | "i2p+tls" => {
                    if !Self::is_i2p_host(host_str) {
                        continue
                    }
                    trace!(
                        target: "net::hosts::filter_addresses",
                        "[I2p] Valid: {host_str}"
                    );
                }

                _ => continue,
            }

            // Store this peer on Dark list if we do not support this transport
            // or if this peer is IPV6 and we do not support IPV6.
            // We will personally ignore this peer but still send it to others in
            // Protocol Addr to ensure all transports get propagated.
            if !settings.allowed_transports.contains(&addr_.scheme().to_string()) ||
                (!self.ipv6_available.load(Ordering::SeqCst) && self.is_ipv6(addr_))
            {
                self.container.store_or_update(HostColor::Dark, addr_.clone(), *last_seen);
                self.container.sort_by_last_seen(HostColor::Dark as usize);
                self.container.resize(HostColor::Dark);

                // Delete darklist entries that are older than one day.
                let day = 86400;
                self.container.refresh(HostColor::Dark, day);

                // If the scheme is not found in mixed_transports we can not connect to this host
                if !settings.mixed_transports.contains(&addr_.scheme().to_string()) {
                    continue;
                }
            }

            // Reject this peer if it's already stored on the Gold, White or Grey list.
            //
            // We do this last since it is the most expensive operation.
            if self.container.contains(HostColor::Gold as usize, addr_) ||
                self.container.contains(HostColor::White as usize, addr_) ||
                self.container.contains(HostColor::Grey as usize, addr_)
            {
                debug!(target: "net::hosts::filter_addresses", "[{addr_}] exists! Skipping");
                continue
            }

            ret.push((addr_.clone(), *last_seen));
        }

        ret
    }

    /// Method to fetch the last_seen field for a give address when we do
    /// not know what hostlist it is on.
    pub fn fetch_last_seen(&self, addr: &Url) -> Option<u64> {
        if self.container.contains(HostColor::Gold as usize, addr) {
            self.container.get_last_seen(HostColor::Gold as usize, addr)
        } else if self.container.contains(HostColor::White as usize, addr) {
            self.container.get_last_seen(HostColor::White as usize, addr)
        } else if self.container.contains(HostColor::Grey as usize, addr) {
            self.container.get_last_seen(HostColor::Grey as usize, addr)
        } else {
            None
        }
    }

    /// Downgrade host to Greylist, remove from Gold or White list.
    pub async fn greylist_host(&self, addr: &Url, last_seen: u64) -> Result<()> {
        debug!(target: "net::hosts:greylist_host()", "Downgrading addr={addr}");
        self.move_host(addr, last_seen, HostColor::Grey).await?;

        // Free up this addr for future operations.
        self.unregister(addr);

        Ok(())
    }

    pub async fn whitelist_host(&self, addr: &Url, last_seen: u64) -> Result<()> {
        debug!(target: "net::hosts:whitelist_host()", "Upgrading addr={addr}");
        self.move_host(addr, last_seen, HostColor::White).await?;

        // Free up this addr for future operations.
        self.unregister(addr);

        Ok(())
    }

    /// A single function for moving hosts between hostlists. Called on the following occasions:
    ///
    /// * When we cannot connect to a peer: move to grey, remove from white and gold.
    /// * When a peer disconnects from us: move to grey, remove from white and gold.
    /// * When the refinery passes successfully: move to white, remove from greylist.
    /// * When we connect to a peer, move to gold, remove from white or grey.
    /// * When we add a peer to the black list: move to black, remove from all other lists.
    ///
    /// Note that this method puts a given Url into the "Move" state but does not reset the
    /// state afterwards. This is because the next state will differ depending on its usage.
    /// The state transition from `Move` to `Connected` or `Suspend` are both valid operations.
    /// In some cases, `unregister()` can be called after `move_host()` to explicitly mark
    /// the host state as `Free`.
    pub(in crate::net) async fn move_host(
        &self,
        addr: &Url,
        last_seen: u64,
        destination: HostColor,
    ) -> Result<()> {
        debug!(target: "net::hosts::move_host()", "Trying to move addr={addr} destination={destination:?}");

        // If we cannot register this address as move, this will simply return here.
        self.try_register(addr.clone(), HostState::Move)?;

        debug!(target: "net::hosts::move_host()", "Moving addr={} destination={destination:?}",
            addr.clone());

        match destination {
            // Downgrade to grey. Remove from white and gold.
            HostColor::Grey => {
                self.container.remove_if_exists(HostColor::Gold, addr);
                self.container.remove_if_exists(HostColor::White, addr);

                self.container.store_or_update(HostColor::Grey, addr.clone(), last_seen);
                self.container.sort_by_last_seen(HostColor::Grey as usize);
                self.container.resize(HostColor::Grey);
            }

            // Remove from Greylist, add to Whitelist. Called by the Refinery.
            HostColor::White => {
                self.container.remove_if_exists(HostColor::Grey, addr);

                self.container.store_or_update(HostColor::White, addr.clone(), last_seen);
                self.container.sort_by_last_seen(HostColor::White as usize);
                self.container.resize(HostColor::White);
            }

            // Upgrade to gold. Remove from white or grey.
            HostColor::Gold => {
                self.container.remove_if_exists(HostColor::Grey, addr);
                self.container.remove_if_exists(HostColor::White, addr);

                self.container.store_or_update(HostColor::Gold, addr.clone(), last_seen);
                self.container.sort_by_last_seen(HostColor::Gold as usize);
            }

            // Move to black. Remove from all other lists.
            HostColor::Black => {
                // We ignore UNIX sockets here so we will just work
                // with stuff that has host_str().
                if addr.host_str().is_some() {
                    // Localhost connections should never enter the blacklist
                    // This however allows any Tor, Nym and I2p connections.
                    if !self.settings.read().await.localnet && self.is_local_host(addr) {
                        return Ok(());
                    }

                    self.container.remove_if_exists(HostColor::Grey, addr);
                    self.container.remove_if_exists(HostColor::White, addr);
                    self.container.remove_if_exists(HostColor::Gold, addr);

                    self.container.store_or_update(HostColor::Black, addr.clone(), last_seen);
                }
            }

            HostColor::Dark => return Err(Error::InvalidHostColor),
        }

        Ok(())
    }

    /// Upon version exchange, the node reports our external network address to us.
    /// Accumulate them here in a ring buffer.
    pub(in crate::net) fn add_auto_addr(&self, addr: Ipv6Addr) {
        let mut auto_addrs = self.auto_self_addrs.lock().unwrap();
        auto_addrs.push(addr);
    }

    /// Pick the most frequent occuring reported external address from other nodes as
    /// our auto ipv6 address.
    pub fn guess_auto_addr(&self) -> Option<Ipv6Addr> {
        let mut auto_addrs = self.auto_self_addrs.lock().unwrap();
        let items = auto_addrs.make_contiguous();
        most_frequent_or_any(items)
    }

    /// The external_addrs is set by the user but we need the actual addresses.
    /// If the external_addr is set to `[::]` (unspecified), then replace it with the
    /// the best guess from `guess_auto_addr()`.
    /// Also if the port is 0, we lookup the port from the `InboundSession`.
    pub async fn external_addrs(&self) -> Vec<Url> {
        let mut external_addrs = self.settings.read().await.external_addrs.clone();
        for ext_addr in &mut external_addrs {
            // We must patch the port first since InboundSession hashmap used to lookup
            // the port number uses the inbound address.
            let _ = self.patch_port(ext_addr);
            let _ = self.patch_auto_addr(ext_addr);
        }
        external_addrs
    }

    /// Make a best effort guess from the most frequently reported ipv6 auto address
    /// to set any unspecified ipv6 addrs: `external_addrs = ["tcp://[::]:1365"]`.
    fn patch_auto_addr(&self, ext_addr: &mut Url) -> Option<()> {
        if ext_addr.scheme() != "tcp" && ext_addr.scheme() != "tcp+tls" {
            return None
        }

        let ext_host = ext_addr.host()?;
        // Is it an Ipv6 listener?
        let Host::Ipv6(ext_ip) = ext_host else { return None };
        // We are only interested if it's [::]
        if !ext_ip.is_unspecified() {
            return None
        }

        // Get our auto-discovered IP
        let auto_addr = self.guess_auto_addr()?;

        // Do the actual replacement of the host part of the URL
        ext_addr.set_ip_host(IpAddr::V6(auto_addr)).ok()?;
        Some(())
    }

    /// If the port number specified is 0, then replace it with whatever the OS has assigned
    /// as a port for that inbound.
    fn patch_port(&self, ext_addr: &mut Url) -> Option<()> {
        // Only patch URLs with port set to 0.
        if ext_addr.port()? != 0 {
            return None
        }

        // TODO:
        // InboundSession needs a HashMap: Url listen addr -> u16 port numbers.
        // Lookup the external_addr from InboundSession to get the port number
        //
        // ext_addr.set_port(my_new_port_number);
        //

        None
    }

    #[cfg(feature = "p2p-i2p")]
    fn is_i2p_host(host: &str) -> bool {
        if !host.ends_with(".i2p") {
            return false
        }

        // Two kinds of address
        // 1. wvbtv6i6njxdtxwsgsr3d4xejdtsy6n7s3d2paqgigjkv3fv5imq.b32.i2p
        // 2. node.darkfi.i2p
        let name = host.trim_end_matches(".i2p");

        if name.ends_with(".b32") {
            let b32 = name.trim_end_matches(".b32");
            let decoded = crate::util::encoding::base32::decode(b32);
            // decoded should be a SHA256 hash
            return decoded.is_some() && decoded.unwrap().len() == 32
        }

        name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    }
}

/// We need a convenience method from Rust's unstable feature "ip".
/// When <https://github.com/rust-lang/rust/issues/27709> is stablized we can remove this.
trait UnstableFeatureIp {
    fn unstable_is_global(&self) -> bool;
}

impl UnstableFeatureIp for Ipv4Addr {
    // Copied from: https://github.com/rust-lang/rust/blob/ea99e81485ff5d82cabba9af5d1c21293737cc16/library/core/src/net/ip_addr.rs#L839
    #[inline]
    fn unstable_is_global(&self) -> bool {
        !(self.octets()[0] == 0 // "This network"
            || self.is_private()
            // is_shared https://github.com/rust-lang/rust/blob/ea99e81485ff5d82cabba9af5d1c21293737cc16/library/core/src/net/ip_addr.rs#L875
            || self.octets()[0] == 100 && (self.octets()[1] & 0b1100_0000 == 0b0100_0000)
            || self.is_loopback()
            || self.is_link_local()
            // addresses reserved for future protocols (`192.0.0.0/24`)
            // .9 and .10 are documented as globally reachable so they're excluded
            || (
                self.octets()[0] == 192 && self.octets()[1] == 0 && self.octets()[2] == 0
                && self.octets()[3] != 9 && self.octets()[3] != 10
            )
            || self.is_documentation()
            // is_benchmarking https://github.com/rust-lang/rust/blob/ea99e81485ff5d82cabba9af5d1c21293737cc16/library/core/src/net/ip_addr.rs#L902
            || self.octets()[0] == 198 && (self.octets()[1] & 0xfe) == 18
            // is_reserved https://github.com/rust-lang/rust/blob/ea99e81485ff5d82cabba9af5d1c21293737cc16/library/core/src/net/ip_addr.rs#L938
            || self.octets()[0] & 240 == 240 && !self.is_broadcast()
            || self.is_broadcast())
    }
}

impl UnstableFeatureIp for Ipv6Addr {
    // Copied from: https://github.com/rust-lang/rust/blob/ea99e81485ff5d82cabba9af5d1c21293737cc16/library/core/src/net/ip_addr.rs#L1598
    #[inline]
    fn unstable_is_global(&self) -> bool {
        !(self.is_unspecified()
            || self.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(self.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(self.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(self.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(self.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(self.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
                    || matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if (0x20..=0x3F).contains(&b))
                ))
            // 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
            // IANA says N/A.
            || matches!(self.segments(), [0x2002, _, _, _, _, _, _, _])
            // is_documentation https://github.com/rust-lang/rust/blob/ea99e81485ff5d82cabba9af5d1c21293737cc16/library/core/src/net/ip_addr.rs#L1754
            || matches!(self.segments(), [0x2001, 0xdb8, ..] | [0x3fff, 0..=0x0fff, ..])
            // Segment Routing (SRv6) SIDs (`5f00::/16`)
            || matches!(self.segments(), [0x5f00, ..])
            || self.is_unique_local()
            || self.is_unicast_link_local())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::sleep;

    #[test]
    fn test_is_local_host() {
        let settings = Settings {
            localnet: false,
            external_addrs: vec![
                Url::parse("tcp://foo.bar:123").unwrap(),
                Url::parse("tcp://lol.cat:321").unwrap(),
            ],
            ..Default::default()
        };
        let hosts = Hosts::new(Arc::new(AsyncRwLock::new(settings)));

        let local_hosts: Vec<Url> = vec![
            Url::parse("tcp://localhost").unwrap(),
            Url::parse("tcp://127.0.0.1").unwrap(),
            Url::parse("tcp+tls://[::1]").unwrap(),
            Url::parse("tcp://localhost.localdomain").unwrap(),
            Url::parse("tcp://192.168.10.65").unwrap(),
        ];
        for host in local_hosts {
            eprintln!("{host}");
            assert!(hosts.is_local_host(&host));
        }
        let remote_hosts: Vec<Url> = vec![
            Url::parse("https://dyne.org").unwrap(),
            Url::parse("tcp://77.168.10.65:2222").unwrap(),
            Url::parse("tcp://[2345:0425:2CA1:0000:0000:0567:5673:23b5]").unwrap(),
            Url::parse("http://eweiibe6tdjsdprb4px6rqrzzcsi22m4koia44kc5pcjr7nec2rlxyad.onion")
                .unwrap(),
        ];
        for host in remote_hosts {
            assert!(!hosts.is_local_host(&host))
        }
    }

    #[test]
    fn test_is_ipv6() {
        let settings = Settings { ..Default::default() };
        let hosts = Hosts::new(Arc::new(AsyncRwLock::new(settings)));

        let ipv6_hosts: Vec<Url> = vec![
            Url::parse("tcp+tls://[::1]").unwrap(),
            Url::parse("tcp://[2001:0000:130F:0000:0000:09C0:876A:130B]").unwrap(),
            Url::parse("tcp://[2345:0425:2CA1:0000:0000:0567:5673:23b5]").unwrap(),
        ];

        let ipv4_hosts: Vec<Url> = vec![
            Url::parse("tcp://192.168.10.65").unwrap(),
            Url::parse("https://dyne.org").unwrap(),
            Url::parse("tcp+tls://agorism.xyz").unwrap(),
        ];

        for host in ipv6_hosts {
            assert!(hosts.is_ipv6(&host))
        }

        for host in ipv4_hosts {
            assert!(!hosts.is_ipv6(&host))
        }
    }

    #[test]
    fn test_block_all_ports() {
        let settings = Settings { ..Default::default() };
        let hosts = Hosts::new(Arc::new(AsyncRwLock::new(settings)));

        let blacklist1 = Url::parse("tcp+tls://nietzsche.king:333").unwrap();
        let blacklist2 = Url::parse("tcp+tls://agorism.xyz").unwrap();

        hosts.container.store(HostColor::Black as usize, blacklist1.clone(), 0);
        hosts.container.store(HostColor::Black as usize, blacklist2.clone(), 0);

        assert!(hosts.block_all_ports(&blacklist2));
        assert!(!hosts.block_all_ports(&blacklist1));
    }

    #[test]
    fn test_store() {
        let last_seen = UNIX_EPOCH.elapsed().unwrap().as_secs();

        let settings = Settings { ..Default::default() };
        let hosts = Hosts::new(Arc::new(AsyncRwLock::new(settings)));

        let grey_hosts = vec![
            Url::parse("tcp://localhost:3921").unwrap(),
            Url::parse("tor://[::1]:21481").unwrap(),
            Url::parse("tcp://192.168.10.65:311").unwrap(),
            Url::parse("tcp+tls://0.0.0.0:2312").unwrap(),
            Url::parse("tcp://255.255.255.255:2131").unwrap(),
        ];

        for addr in &grey_hosts {
            hosts.container.store(HostColor::Grey as usize, addr.clone(), last_seen);
        }
        assert!(!hosts.container.is_empty(HostColor::Grey));

        let white_hosts = vec![
            Url::parse("tcp://localhost:3921").unwrap(),
            Url::parse("tor://[::1]:21481").unwrap(),
            Url::parse("tcp://192.168.10.65:311").unwrap(),
            Url::parse("tcp+tls://0.0.0.0:2312").unwrap(),
            Url::parse("tcp://255.255.255.255:2131").unwrap(),
        ];

        for host in &white_hosts {
            hosts.container.store(HostColor::White as usize, host.clone(), last_seen);
        }
        assert!(!hosts.container.is_empty(HostColor::White));

        let gold_hosts = vec![
            Url::parse("tcp://dark.fi:80").unwrap(),
            Url::parse("tcp://http.cat:401").unwrap(),
            Url::parse("tcp://foo.bar:111").unwrap(),
        ];

        for host in &gold_hosts {
            hosts.container.store(HostColor::Gold as usize, host.clone(), last_seen);
        }

        assert!(hosts.container.contains(HostColor::Grey as usize, &grey_hosts[0]));
        assert!(hosts.container.contains(HostColor::White as usize, &white_hosts[1]));
        assert!(hosts.container.contains(HostColor::Gold as usize, &gold_hosts[2]));
    }

    #[test]
    fn test_refresh() {
        smol::block_on(async {
            let settings = Settings { ..Default::default() };
            let hosts = Hosts::new(Arc::new(AsyncRwLock::new(settings)));
            let old_timestamp = 1720000000;

            // Insert 5 items into the darklist with an old timestamp.
            for i in 0..5 {
                let last_seen = old_timestamp + i;
                let url = Url::parse(&format!("tcp://old_darklist{i}:123")).unwrap();
                hosts.container.store(HostColor::Dark as usize, url.clone(), last_seen);
            }

            // Insert another 5 items into the darklist with a recent timestamp.
            for i in 0..5 {
                let last_seen = UNIX_EPOCH.elapsed().unwrap().as_secs();
                let url = Url::parse(&format!("tcp://new_darklist{i}:123")).unwrap();
                hosts.container.store(HostColor::Dark as usize, url.clone(), last_seen);
            }

            // Delete all items that are older than a day.
            let day = 86400;
            hosts.container.refresh(HostColor::Dark, day);

            let darklist = hosts.container.hostlists[HostColor::Dark as usize].read().unwrap();
            assert!(darklist.len() == 5);

            for (_, last_seen) in darklist.iter() {
                assert!(*last_seen > old_timestamp);
            }

            drop(darklist);
            let now = UNIX_EPOCH.elapsed().unwrap().as_secs();
            let future_timestamp = now + 100;

            // Insert another 5 items into the darklist with a timestamp from the future.
            for i in 0..5 {
                let last_seen = future_timestamp;
                let url = Url::parse(&format!("tcp://future_darklist{i}:123")).unwrap();
                hosts.container.store(HostColor::Dark as usize, url.clone(), last_seen);
            }

            hosts.container.refresh(HostColor::Dark, day);

            // Darklist length should be 5 + 5 (new entries + future entries)
            let darklist = hosts.container.hostlists[HostColor::Dark as usize].read().unwrap();
            assert!(darklist.len() == 10);
        });
    }

    #[test]
    fn test_get_last() {
        smol::block_on(async {
            let settings = Settings { ..Default::default() };
            let hosts = Hosts::new(Arc::new(AsyncRwLock::new(settings)));

            // Build up a hostlist
            for i in 0..10 {
                sleep(1).await;
                let last_seen = UNIX_EPOCH.elapsed().unwrap().as_secs();
                let url = Url::parse(&format!("tcp://whitelist{i}:123")).unwrap();
                hosts.container.store(HostColor::White as usize, url.clone(), last_seen);
            }

            for (url, last_seen) in
                hosts.container.hostlists[HostColor::White as usize].read().unwrap().iter()
            {
                println!("{url} {last_seen}");
            }

            let entry = hosts.container.fetch_last(HostColor::White).unwrap();
            println!("last entry: {} {}", entry.0, entry.1);
        });
    }

    #[test]
    fn test_is_p2p_host() {
        assert!(Hosts::is_i2p_host("tm7bz5qfh73id33yjpshxmesrqedoz2ckghd3levktqywcrramwq.b32.i2p"));
        assert!(!Hosts::is_i2p_host("randomstring.b32.i2p"));
        assert!(Hosts::is_i2p_host("node.dark.fi.i2p"));
        assert!(!Hosts::is_i2p_host("node.dark.fi"));
    }

    // Test tcp endpoint is changed to tor and tcp will not be used to
    // connect to any host directly
    #[test]
    fn test_transport_tor_mixed_with_tcp_fetch() {
        let host_container = HostContainer::new();
        host_container.store_or_update(
            HostColor::Grey,
            Url::parse("tcp://dark.fi:28880").unwrap(),
            0,
        );

        let fetched_hosts = host_container.fetch(
            HostColor::Grey,
            &["tor+tls".to_string(), "tcp".to_string(), "tor".to_string()],
            &["tcp".to_string()],
            Url::parse("socks5://127.0.0.1:9050").ok(),
            None,
        );

        assert_eq!(fetched_hosts.len(), 1);
        assert_eq!(fetched_hosts[0].0.to_string(), "tor://dark.fi:28880/");
    }

    // Test when both tor_socks5_proxy and nym_socks5_proxy are passed
    // tcp+tls endpoint is changed to socks5+tls and the endpoint is changed to two
    // endpoints where one is routed through tor and another through nym
    #[test]
    fn test_transport_socks5_mixed_with_tcp_through_tor_and_nym_proxy_fetch() {
        let host_container = HostContainer::new();
        host_container.store_or_update(
            HostColor::Grey,
            Url::parse("tcp+tls://dark.fi:28880").unwrap(),
            0,
        );
        let tor_socks5_proxy_url = Url::parse("socks5://127.0.0.1:9050").ok();
        let nym_socks5_proxy_url = Url::parse("socks5://127.0.0.1:1080").ok();

        let fetched_hosts = host_container.fetch(
            HostColor::Grey,
            &["socks5".to_string(), "socks5+tls".to_string()],
            &["tcp+tls".to_string()],
            tor_socks5_proxy_url.clone(),
            nym_socks5_proxy_url.clone(),
        );

        assert_eq!(fetched_hosts.len(), 2);
        assert!(
            fetched_hosts[0].0.scheme() == "socks5+tls" &&
                fetched_hosts[1].0.scheme() == "socks5+tls"
        );
        assert_eq!(
            fetched_hosts
                .iter()
                .filter(|h| h.0.port() == tor_socks5_proxy_url.as_ref().unwrap().port())
                .count(),
            1
        );
        assert_eq!(
            fetched_hosts
                .iter()
                .filter(|h| h.0.port() == nym_socks5_proxy_url.as_ref().unwrap().port())
                .count(),
            1
        );
    }

    // Test tor endpoint is changed to socks5 and tor will not be used to
    // connect to any host directly and tor endpoints are not routed through nym
    #[test]
    fn test_transport_socks5_mixed_with_tor_fetch() {
        let host_container = HostContainer::new();
        let addr = "eweiibe6tdjsdprb4px6rqrzzcsi22m4koia44kc5pcjr7nec2rlxyad.onion:23330";
        host_container.store_or_update(
            HostColor::Grey,
            Url::parse(&format!("tor://{addr}")).unwrap(),
            0,
        );
        let tor_socks5_proxy_url = Url::parse("socks5://127.0.0.1:9050").ok();
        let nym_socks5_proxy_url = Url::parse("socks5://127.0.0.1:1080").ok();

        let fetched_hosts = host_container.fetch(
            HostColor::Grey,
            &["socks5".to_string(), "socks5+tls".to_string(), "tor".to_string()],
            &["tor".to_string()],
            tor_socks5_proxy_url.clone(),
            nym_socks5_proxy_url,
        );

        assert_eq!(fetched_hosts.len(), 1);
        let mixed_url = fetched_hosts[0].0.clone();
        assert_eq!(mixed_url.scheme(), tor_socks5_proxy_url.as_ref().unwrap().scheme());
        assert_eq!(mixed_url.host(), tor_socks5_proxy_url.as_ref().unwrap().host());
        assert_eq!(mixed_url.port(), tor_socks5_proxy_url.as_ref().unwrap().port());
        assert_eq!(mixed_url.path_segments().unwrap().next(), Some(addr));
    }

    // Test the tcp endpoint is changed to two endpoints socks5 and tor.
    #[test]
    fn test_transport_tor_and_socks5_mixed_with_tcp_fetch() {
        let host_container = HostContainer::new();
        host_container.store_or_update(
            HostColor::Grey,
            Url::parse("tcp://dark.fi:28880").unwrap(),
            0,
        );

        let fetched_hosts = host_container.fetch(
            HostColor::Grey,
            &[
                "tor".to_string(),
                "tor+tls".to_string(),
                "socks5".to_string(),
                "socks5+tls".to_string(),
            ],
            &["tcp".to_string()],
            Url::parse("socks5://127.0.0.1:9050").ok(),
            None,
        );

        assert_eq!(fetched_hosts.len(), 2);
        let endpoints: Vec<_> = fetched_hosts.iter().map(|item| item.0.scheme()).collect();
        assert!(endpoints.iter().all(|&scheme| scheme == "tor" || scheme == "socks5"));
    }
}
