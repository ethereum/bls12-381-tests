# Test format: BLS sign message

[Batch verify](https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407) the signatures against the given pubkeys and one messages.

## Test case format

The test data is declared in a `data.yaml` file:

```yaml
input:
  pubkey: List[bytes48] -- the pubkeys
  message: List[bytes32] -- the messages
  signature: List[bytes96] -- the signatures to verify against pubkeys and messages
output: bool  -- VALID or INVALID
```

All byte(s) fields are encoded as strings, hexadecimal encoding, prefixed with `0x`.
