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

use darkfi::{geode::hash_to_string, rpc::util::json_map};
use tinyjson::JsonValue;

#[derive(Clone, Debug)]
pub enum ResourceStatus {
    Downloading,
    Seeding,
    Discovering,
    Incomplete,
}

#[derive(Clone, Debug)]
pub struct Resource {
    pub hash: blake3::Hash,
    pub status: ResourceStatus,
    pub chunks_total: u64,
    pub chunks_downloaded: u64,
}

impl From<Resource> for JsonValue {
    fn from(rs: Resource) -> JsonValue {
        json_map([
            ("hash", JsonValue::String(hash_to_string(&rs.hash))),
            (
                "status",
                JsonValue::String(
                    match rs.status {
                        ResourceStatus::Downloading => "downloading",
                        ResourceStatus::Seeding => "seeding",
                        ResourceStatus::Discovering => "discovering",
                        ResourceStatus::Incomplete => "incomplete",
                    }
                    .to_string(),
                ),
            ),
            ("chunks_total", JsonValue::Number(rs.chunks_total as f64)),
            ("chunks_downloaded", JsonValue::Number(rs.chunks_downloaded as f64)),
        ])
    }
}
