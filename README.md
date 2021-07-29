# BLS 12-381 tests

This repository provides a test-suite for the `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` ciphersuite (following [draft 4](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04)),
as used in Ethereum 2.0 [BLS Signature APIs](https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#bls-signatures),
as well as common extensions such as signature-sets ([batch aggregate verification](https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407)) and serialization.

The test suite is generated with python, and can be downloaded via the releases.
We suggest the following for integration into your testing pipeline:

```shell
TESTS_VERSION=v0.1.0
wget https://github.com/ethereum/bls12-381-tests/releases/download/$(TESTS_VERSION)/tests.tar.gz -O - | tar -xz -C my-test/vector-path/here/bls-tests
```

## Resources

- [IETF BLS Signature Scheme versions](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/)
- [IETF BLS Signature Scheme draft 4](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04)
- [Finite Field Arithmetic](http://www.springeronline.com/sgw/cda/pageitems/document/cda_downloaddocument/0,11996,0-0-45-110359-0,00.pdf)
- Chapter 2 of [Elliptic Curve Cryptography](http://cacr.uwaterloo.ca/ecc/). Darrel Hankerson, Alfred Menezes, and Scott Vanstone

## Test format

The BLS test suite runner has the following handlers:

- [`aggregate_verify`](formats/aggregate_verify.md)
- [`aggregate`](formats/aggregate.md)
- [`fast_aggregate_verify`](formats/fast_aggregate_verify.md)
- [`sign`](formats/sign.md)
- [`verify`](formats/verify.md)
- [`hash_to_G2`](formats/hash_to_G2.md)
- [`deserialization_G1`](formats/deserialization_G1.md)
- [`deserialization_G2](formats/deserialization_G2.md)


## Test generation

```shell
# Create a virtual environment
python -m venv venv
# Activate the environment
source venv/bin/activate
# Install dependencies
pip install -r requirements.txt
# Create output dir
mkdir out
# Run test generator
python main.py --output-dir=out --encoding=yaml
```

## License

CC0 1.0 Universal, see [`LICENSE`](./LICENSE) file.
