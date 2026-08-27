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

use std::{
    io::{Cursor, Read, Result, Write},
    ptr,
};

#[allow(unused_imports)]
use tiny_keccak::{Hasher, Keccak};

// Prefix of tiny-keccak 2.0 `KeccakState` (see lib.rs around the KeccakState
// definition). Mode is omitted: a `#[repr(C)]` enum is larger than
// tiny-keccak's Mode, so overlaying it made this type bigger than `Keccak`
// and rustc 1.78+ rejects that as `invalid_reference_casting`.
#[repr(C)]
struct KeccakStatePrefix {
    buffer: [u8; 200],
    offset: usize,
    rate: usize,
    delim: u8,
}

unsafe fn serialize_keccak<W: Write>(keccak: &Keccak, writer: &mut W) -> Result<()> {
    let p = keccak as *const Keccak as *const KeccakStatePrefix;
    writer.write_all(&*ptr::addr_of!((*p).buffer))?;
    writer.write_all(&(*ptr::addr_of!((*p).offset) as u64).to_le_bytes())?;
    writer.write_all(&(*ptr::addr_of!((*p).rate) as u64).to_le_bytes())?;
    writer.write_all(&[*ptr::addr_of!((*p).delim)])?;
    Ok(())
}

unsafe fn deserialize_keccak<R: Read>(reader: &mut R) -> Result<Keccak> {
    let mut keccak = Keccak::v256();
    let p = &mut keccak as *mut Keccak as *mut KeccakStatePrefix;

    reader.read_exact(&mut *ptr::addr_of_mut!((*p).buffer))?;

    let mut offset_bytes = [0u8; 8];
    reader.read_exact(&mut offset_bytes)?;
    ptr::write(ptr::addr_of_mut!((*p).offset), u64::from_le_bytes(offset_bytes) as usize);

    let mut rate_bytes = [0u8; 8];
    reader.read_exact(&mut rate_bytes)?;
    ptr::write(ptr::addr_of_mut!((*p).rate), u64::from_le_bytes(rate_bytes) as usize);

    let mut delim_byte = [0u8; 1];
    reader.read_exact(&mut delim_byte)?;
    ptr::write(ptr::addr_of_mut!((*p).delim), delim_byte[0]);
    // Mode stays Absorbing from Keccak::v256().

    Ok(keccak)
}

pub fn keccak_to_bytes(keccak: &Keccak) -> Vec<u8> {
    let mut bytes = vec![];
    unsafe { serialize_keccak(keccak, &mut bytes).unwrap() }
    bytes
}

pub fn keccak_from_bytes(bytes: &[u8]) -> Keccak {
    let mut cursor = Cursor::new(bytes);
    unsafe { deserialize_keccak(&mut cursor).unwrap() }
}

#[test]
fn test_keccak_serde() {
    let mut keccak = Keccak::v256();
    keccak.update(b"foobar");

    let ser = keccak_to_bytes(&keccak);

    let mut digest1 = [0u8; 32];
    keccak.finalize(&mut digest1);

    let de = keccak_from_bytes(&ser);
    let mut digest2 = [0u8; 32];
    de.finalize(&mut digest2);

    println!("{digest1:?}");
    println!("{digest2:?}");

    assert_eq!(digest1, digest2);
}
