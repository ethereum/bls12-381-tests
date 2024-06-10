# Test format: 'BLS12_G2MUL'

point multiplication in G2

## Test case format

The test data is declared in a 'json' file:

```
[
    {
        "Input": call expects 288 bytes as an input that is interpreted as byte concatenation
         of encoding of G2 point (256 bytes) and encoding of a scalar value (32 bytes),
        "Name": the name of the test,
        "Expected": single G2 point (256 bytes),
        "Gas": the cost of the gas,
        "NoBenchmark": True/False
    },
    ...
]
```

All byte(s) fields are encoded as strings, hexadecimal encoding
