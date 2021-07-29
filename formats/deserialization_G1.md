# Test format: Deserialization to G1

Deserializaion of a public key should produce a point in G1

## Test case format

The test data is declared in a `data.yaml` file:

```yaml
input: pubkey: bytes48 -- the pubkey
output: bool  -- VALID or INVALID
```

All byte(s) fields are encoded as strings, hexadecimal encoding, prefixed with `0x`.
