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

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use pasta_curves::{
    group::{prime::PrimeCurveAffine, Curve, GroupEncoding, Wnaf},
    pallas,
};

use super::{util::fp_mod_fv, PublicKey, SecretKey};
use crate::error::ContractError;

pub const KDF_SAPLING_PERSONALIZATION: &[u8; 16] = b"DarkFiSaplingKDF";

/// Sapling key agreement for note encryption.
/// Implements section 5.4.4.3 of the Zcash Protocol Specification
pub fn sapling_ka_agree(esk: &SecretKey, pk_d: &PublicKey) -> Result<PublicKey, ContractError> {
    let esk_s = fp_mod_fv(esk.inner());
    // Windowed multiplication is constant time. Hence that is used here vs naive EC mult.
    // Decrypting notes is a an amortized operation, so you want successful rare-case note
    // decryptions to be indistinguishable from the usual case.
    let mut wnaf = Wnaf::new();
    PublicKey::try_from(wnaf.scalar(&esk_s).base(pk_d.inner()))
}

/// Sapling key agreement for many ephemeral keys under one secret.
///
/// Multiplications stay in extended coordinates (the same windowed multiply as
/// [`sapling_ka_agree`]). One field inversion normalizes the whole batch.
/// Each item is the compressed shared secret, the input to [`kdf_sapling`].
pub fn sapling_ka_agree_batch(
    esk: &SecretKey,
    pk_ds: &[PublicKey],
) -> Vec<Result<[u8; 32], ContractError>> {
    if pk_ds.is_empty() {
        return Vec::new();
    }
    let esk_s = fp_mod_fv(esk.inner());
    let mut wnaf = Wnaf::new();
    let mut wnaf_scalar = wnaf.scalar(&esk_s);
    let extended: Vec<pallas::Point> =
        pk_ds.iter().map(|pk| wnaf_scalar.base(pk.inner())).collect();
    let mut affine = vec![<pallas::Affine as PrimeCurveAffine>::identity(); extended.len()];
    <pallas::Point as Curve>::batch_normalize(&extended, &mut affine);
    affine
        .into_iter()
        .map(|point| {
            if bool::from(point.is_identity()) {
                Err(ContractError::IoError("Sapling key agreement produced the identity".into()))
            } else {
                Ok(point.to_bytes())
            }
        })
        .collect()
}

/// Sapling KDF for note encryption.
pub fn kdf_sapling(dhsecret: &PublicKey, epk: &PublicKey) -> Blake2bHash {
    kdf_sapling_compressed(&dhsecret.inner().to_bytes(), epk)
}

/// [`kdf_sapling`] from a compressed shared secret.
///
/// `dhsecret` is the encoding produced by [`sapling_ka_agree_batch`], so the
/// batch path does not invert the shared-secret coordinate a second time.
pub fn kdf_sapling_compressed(dhsecret: &[u8], epk: &PublicKey) -> Blake2bHash {
    // The P.to_bytes() for P ∈ ℙₚ function used on affine curves it not perfectly constant time,
    // but it's close enough. The function returns 0 when P = ∞ is the identity which is the
    // edge case but almost never occurs.
    Blake2bParams::new()
        .hash_length(32)
        .personal(KDF_SAPLING_PERSONALIZATION)
        .to_state()
        .update(dhsecret)
        .update(&epk.inner().to_bytes())
        .finalize()
}
