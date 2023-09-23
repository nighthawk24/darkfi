use darkfi_money_contract::model::MoneyTransferParamsV1;
use darkfi_sdk::{
    crypto::{ContractId, PublicKey},
    db::zkas_db_set,
    error::{ContractError, ContractResult},
    msg,
    pasta::pallas,
    util::{get_verifying_slot, set_return_data},
    ContractCall,
};
use darkfi_serial::{deserialize, Encodable};

use crate::TimelockFunction;

darkfi_sdk::define_contract!(
    init: init_contract,
    exec: process_instruction,
    apply: process_update,
    metadata: get_metadata
);

fn init_contract(_cid: ContractId, _ix: &[u8]) -> ContractResult {
    // We deploy the compiled ZK circuit on-chain by embedding the code in WASM
    // and then place it into the database like this:
    let unlock_bincode = include_bytes!("../proof/unlock.zk.bin");
    zkas_db_set(&unlock_bincode[..])?;

    Ok(())
}

fn get_metadata(_cid: ContractId, ix: &[u8]) -> ContractResult {
    let (call_idx, calls): (u32, Vec<ContractCall>) = deserialize(ix)?;
    if call_idx >= calls.len() as u32 {
        msg!("Error: call_idx >= calls.len()");
        return Err(ContractError::Internal)
    }

    match TimelockFunction::try_from(calls[call_idx as usize].data[0])? {
        TimelockFunction::Unlock => {
            // Here we expect that this call_idx is 1, and the previous call_idx is 0.
            // We'll take the params from the previous call and fetch `user_data_enc`
            // from it. For demo purposes we'll hardcode a single input, but this can
            // easily be expanded into a for loop iterating over all inputs in the
            // `Money::Transfer` contract call.
            assert!(call_idx == 1);

            // Deserialize the parameters from the previous contract call
            let money_params: MoneyTransferParamsV1 = deserialize(&calls[0].data[1..])?;

            // Grab `user_data_enc` from the input
            let user_data_enc = money_params.inputs[0].user_data_enc;

            // Grab the current block height (get_verifying_slot returns u64)
            let block_height = pallas::Base::from(get_verifying_slot());

            // Now construct the public inputs for the ZK proof
            let zk_public_inputs: Vec<(String, Vec<pallas::Base>)> =
                vec![("Unlock".to_string(), vec![block_height, user_data_enc])];

            // In this contract call, we don't have to verify any signatures,
            // so we leave them empty
            let signature_pubkeys: Vec<PublicKey> = vec![];

            // Now we serialize everything gathered and return it.
            // This data will be fed into the ZK verification process.
            let mut metadata = vec![];
            zk_public_inputs.encode(&mut metadata)?;
            signature_pubkeys.encode(&mut metadata)?;

            // Export the data
            Ok(set_return_data(&metadata)?)
        }
    }
}

fn process_instruction(_cid: ContractId, ix: &[u8]) -> ContractResult {
    let (call_idx, calls): (u32, Vec<ContractCall>) = deserialize(ix)?;
    if call_idx >= calls.len() as u32 {
        msg!("Error: call_idx >= calls.len()");
        return Err(ContractError::Internal)
    }

    match TimelockFunction::try_from(calls[call_idx as usize].data[0])? {
        TimelockFunction::Unlock => {
            // In here we could perform anything that we require to do
            // any kind of verification. It is not needed for the timelock
            // since everything that has to be done is enforce the ZK proof.
            //
            // But for example, `::Unlock` could have its own `Params`, and
            // then here we'd assert that the `user_data_enc` from these
            // params is the same as `user_data_enc` in the previous call.

            Ok(set_return_data(&[TimelockFunction::Unlock as u8])?)
        }
    }
}

fn process_update(_cid: ContractId, update_data: &[u8]) -> ContractResult {
    match TimelockFunction::try_from(update_data[0])? {
        // The timelock does not have to perform any state update, so we
        // just return Ok() here.
        TimelockFunction::Unlock => Ok(()),
    }
}
