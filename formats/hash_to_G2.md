# Test format: BLS hash to G2

Hash an arbitrary string to a point on an elliptic curve.

## Test case format

The test data is declared in a `data.yaml` file:

```yaml
input: message: bytes32 -- input message to hash
output: 
  x -- x coordinate of the point P output by the hashing,
  y -- y coordinate of the point P output by the hashing
```

All byte(s) fields are encoded as strings, hexadecimal encoding, prefixed with `0x`.
