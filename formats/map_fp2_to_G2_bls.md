# Test format: 'BLS12_MAP_FP2_TO_G2'

maps extension field element into the G2 point

## Test case format

The test data is declared in a 'json' file:

```
[
    {
        "Input": 128 bytes as an input that is interpreted as a an element of the quadratic extension field,
        "Name": the name of the test,
        "Expected": single G2 point (256 bytes),
        "Gas": the cost of the gas,
        "NoBenchmark": True/False
    },
    ....
]
```

All byte(s) fields are encoded as strings, hexadecimal encoding
