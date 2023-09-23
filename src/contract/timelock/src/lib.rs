use darkfi_sdk::error::ContractError;

#[repr(u8)]
pub enum TimelockFunction {
    Unlock = 0x01,
}

impl TryFrom<u8> for TimelockFunction {
    type Error = ContractError;

    fn try_from(b: u8) -> Result<Self, Self::Error> {
        match b {
            0x01 => Ok(Self::Unlock),
            _ => Err(ContractError::InvalidFunction),
        }
    }
}

#[cfg(not(feature = "no-entrypoint"))]
/// WASM entrypoint functions
pub mod entrypoint;
