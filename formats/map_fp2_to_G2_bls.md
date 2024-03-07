# Test format: 'BLS12_MAP_FP2_TO_G2'

maps extension field element into the G2 point

## Test case format

The test data is declared in a 'json' file:

```
[
    {
        "Input": 64 bytes as an input that is interpreted as an element of the base field.,
        "Name": the name of the test,
        "Expected": single G1 point 128 bytes,
        "Gas": the cost of the gas,
        "NoBenchmark": True/False
    },
    ....
]
```

All byte(s) fields are encoded as strings, hexadecimal encoding

