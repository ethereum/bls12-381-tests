# Test format: Deserialization to G2

Deserializaion of a public key should produce a point in G2

## Test case format

The test data is declared in a `data.yaml` file:

```yaml
input: pubkey: bytes92 -- the pubkey
output: bool  -- VALID or INVALID
```

All byte(s) fields are encoded as strings, hexadecimal encoding, prefixed with `0x`.
