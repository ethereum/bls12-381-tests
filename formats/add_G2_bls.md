# Test format: 'BLS12_G2ADD'

point addition in G2

## Test case format

The test data is declared in a 'json' file:

```
[
    {
        "Input": concatenation of two G1 points (128 bytes each),
        "Name": the name of the test,
        "Expected": single G1 point 128 bytes,
        "Gas": the cost of the gas,
        "NoBenchmark": True/False
    },
    ....
]
```

