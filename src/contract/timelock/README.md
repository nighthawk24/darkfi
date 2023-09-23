# Anonymously timelocking a coin

1. We have a coin `C` which we want to lock from being spent
   up until a certain block height.

A coin `C` consists of:

```
poseidon_hash(
    pub_x,      # X coordinate of the owner's pubkey
    pub_y,      # Y coordinate of the owner's pubkey
    value,      # The value of the coin
    token,      # The token ID of the coin
    serial,     # The unique serial number corresponding to the coin
    spend_hook, # A hook enforcing another contract call once spent
    user_data,  # Arbitrary data appended to the coin
);
```

By committing to the fields using the hash, we _hide_ the inner
values and only make the commitment/coin `C` public. Data inside
it cannot be retrieved this way since the hash function is one-way.

<details>
  <summary>How can we timelock this coin?</summary>

  * `spend_hook` can point to the `timelock` smart contract
  * `user_data` can contain the wanted block height
</details>

## Spending a coin

To spend a coin, we have to _burn_ it. At this point we also enforce
any `spend_hook` that is set in the coin. If the `spend_hook` is not
zero, the smart contract runtime will enforce that the next contract
in line is the contract pointed by `spend_hook`. In our case this is
going to be the `timelock` contract.

The `user_data` from the coin will be blinded with some random value
in order not to reveal it. This will result in `user_data_enc`, which
can then be used by `timelock` to enforce that same data (block height).

# Transaction format

We want to send a timelocked coin to someone.

## Contract calls

1. `Money::Transfer`
2. `Timelock::Unlock`

# The Timelock contract

* The contract will expect that the previous contract call is
  `Money::Transfer`.
* The contract will take `user_data_enc` from that previous call
  and enforce it in the public inputs of the ZK proofs used for
  the timelock.
* Additionally, the contract will fetch the current block height
  in order to plug it into the ZK proof and check for that validity.
* The ZK proof needs to enforce that the current block height (at the
  time of contract execution) is less than `user_data`, which
  represents the timelock height.

Now, if both `Money::Transfer` and `Timelock::Unlock` pass, the
transaction will pass and the coin is able to be spent.
