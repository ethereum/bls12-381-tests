# Test format: 'BLS12_PAIRING_CHECK'

Pairing check.

## Test case format

The test data is declared in a 'json' file:

```
[
    {
        "Input": 384*k bytes as an input that is interpreted as byte concatenation of k slices each
          of them being a byte concatenation of encoding of G1 point (128 bytes) and encoding of a
          G2 point (256 bytes),
        "Name": the name of the test,
        "Expected": scalar value (32 bytes), either 0 or 1,
        "Gas": the cost of the gas,
        "NoBenchmark": true/false
    },
    ....
]
```

All byte(s) fields are encoded as strings, hexadecimal encoding
