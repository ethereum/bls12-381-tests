# Test format: 'BLS12_G1MUL'

point multiplication in G1

## Test case format

The test data is declared in a 'json' file:

```
[
    {
        "Input": 160 bytes as an input that is interpreted as byte concatenation of
         encoding of G1 point (128 bytes) and encoding of a scalar value (32 bytes),
        "Name": the name of the test,
        "Expected": single G1 point 128 bytes,
        "Gas": the cost of the gas,
        "NoBenchmark": True/False
    },
    ....
]
```

All byte(s) fields are encoded as strings, hexadecimal encoding

