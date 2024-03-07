# Test format: 'BLS12_MAP_FP_TO_G1'

maps base field element into the G1 point

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
