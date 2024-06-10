# Test format: 'BLS12_G2ADD'

point addition in G2

## Test case format

The test data is declared in a 'json' file:

```
[
    {
        "Input": 512 bytes as an input that is interpreted as byte concatenation of two G2 points (256 bytes each),
        "Name": the name of the test,
        "Expected": single G2 point (256 bytes),
        "Gas": the cost of the gas,
        "NoBenchmark": True/False
    },
    ...
]
```

All byte(s) fields are encoded as strings, hexadecimal encoding
