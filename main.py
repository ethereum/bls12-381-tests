"""
BLS test vectors generator
"""

from typing import Tuple, Any, Callable, Dict, Generator

import argparse
from pathlib import Path
import json
from ruamel.yaml import YAML

from hashlib import sha256

from py_ecc.bls12_381 import (
    G1,
    G2,
    FQ,
    FQ2,
    add,
    multiply,
    neg,
    is_inf
)

from py_ecc.bls.hash_to_curve import hash_to_G2


def to_bytes32(i):
    return i.to_bytes(32, byteorder='big')


def hash(x):
    return sha256(x).digest()


def encode_hex(value: bytes) -> str:
    return value.hex()


def int_to_big_endian(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')


def int_to_hex(n: int, byte_length: int = None) -> str:
    byte_value = int_to_big_endian(n)
    if byte_length:
        byte_value = byte_value.rjust(byte_length, b'\x00')
    return encode_hex(byte_value)


def hex_to_int(x: str) -> int:
    return int(x, 16)


# gas costs
# TODO to change
BLS12_G1ADD_GAS = 600
BLS12_G2ADD_GAS = 4500
BLS12_G1MUL_GAS = 12000
BLS12_G2MUL_GAS = 55000

# random point in G1
P1 = (
    FQ(
        2642749686785829596817345696055666872043783053155481581788492942917249902143862050648544313423577373440886627275814  # noqa: E501
    ),  # noqa: E501
    FQ(
        3758365293065836235831663685357329573226673833426684174336991792633405517674721205716466791757730149346109800483361  # noqa: E501
    ),  # noqa: E501
)


# random point in G2
P2 = (
    FQ2(
        [
            2492164500931426079025163640852824812322867633561487327988861767918782925114618691347698906331033143057488152854311,  # noqa: E501
            1296003438898513467811811427923539448251934100547963606575856033955925534446513985696904241181481649924224027073384,  # noqa: E501
        ]
    ),
    FQ2(
        [
            2403995578136121235978187296860525416643018865432935587266433984437673369013628886898228883216954086902460896225150,  # noqa: E501
            2021783735792747140008634321371188179203707822883609206755922036803500907979420976539856007028648957203721805595729,  # noqa: E501
        ]
    ),
)


 

DST = b'QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_'
H = sha256
HASH_G2_MESSAGES = [
    (b'',
     '0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a',
     '05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d',
     '0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92',
     '12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6'),
    (b'abc',
     '02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6',
     '139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8',
     '1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48',
     '00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16'),
    (b'abcdef0123456789',
     '121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0',
     '190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c',
     '05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8',
     '0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be'),
    (
    b'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534',
    '11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569',
    '0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e',
    '03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52'),
]


def expect_exception(func, *args):
    try:
        func(*args)
    except Exception:
        pass
    else:
        raise Exception("should have raised exception")


def case01_add_G1():
    # Commutativity
    result_comm1 = add(G1, P1)
    result_comm2 = add(P1, G1)
    assert result_comm1 == result_comm2
    # Identity element
    result_identity_G1 = add(G1, None)
    assert G1 == result_identity_G1
    result_identity_P1 = add(P1, None)
    assert P1 == result_identity_P1
    # Additive negation
    result_neg_G1 = add(G1, neg(G1))
    assert (is_inf(result_neg_G1))
    result_neg_P1 = add(P1, neg(P1))
    assert (is_inf(result_neg_P1))
    # Doubling
    result_doubling_G1 = add(G1, G1)
    assert result_doubling_G1 == multiply(G1, 2)
    result_doubling_P1 = add(P1, P1)
    assert result_doubling_P1 == multiply(P1, 2)

    yield 'add_G1_bls', [
        {
        "Input": int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)) + int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)),
        "Name": "bls_g1add_g1+p1",
        "Expected": int_to_hex(int(result_comm1[0]), 64) + (int_to_hex(int(result_comm1[1]), 64)),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)) + int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)),
        "Name": "bls_g1add_p1+g1",
        "Expected": int_to_hex(int(result_comm2[0]), 64) + (int_to_hex(int(result_comm2[1]), 64)),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Name": "bls_g1add_(g1+0=g1)",
        "Expected": int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Name": "bls_g1add_(p1+0=p1)",
        "Expected": int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)) + int_to_hex(int(neg(G1)[0]), 64) + (int_to_hex(int(neg(G1)[1]), 64)),
        "Name": "bls_g1add_(g1-g1=0)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)) + int_to_hex(int(neg(P1)[0]), 64) + (int_to_hex(int(neg(P1)[1]), 64)),
        "Name": "bls_g1add_(p1-p1=0)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)) + int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)),
        "Name": "bls_g1add_(g1+g1=2*g1)",
        "Expected": int_to_hex(int(result_doubling_G1[0]), 64) + (int_to_hex(int(result_doubling_G1[1]), 64)),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)) + int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)),
        "Name": "bls_g1add_(p1+p1=2*p1)",
        "Expected": int_to_hex(int(result_doubling_P1[0]), 64) + (int_to_hex(int(result_doubling_P1[1]), 64)),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        }
    ]


def case02_add_G2():
    # Commutativity
    result_comm1 = add(G2, P2)
    result_comm2 = add(P2, G2)
    assert result_comm1 == result_comm2
    # Identity element
    result_identity_G2 = add(G2, None)
    assert G2 == result_identity_G2
    result_identity_P2 = add(P2, None)
    assert P2 == result_identity_P2
    # Additive negation
    result_neg_G2 = add(G2, neg(G2))
    assert (is_inf(result_neg_G2))
    result_neg_P2 = add(P2, neg(P2))
    assert (is_inf(result_neg_P2))
    # Doubling
    result_doubling_G2 = add(G2, G2)
    assert result_doubling_G2 == multiply(G2, 2)
    result_doubling_P2 = add(P2, P2)
    assert result_doubling_P2 == multiply(P2, 2)
    yield 'add_G2_bls', [
        {
        "Input": int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64) + int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64),
        "Name": "bls_g2add_g2+p2",
        "Expected": int_to_hex(int(result_comm1[0].coeffs[0]), 64) + int_to_hex(int(result_comm1[0].coeffs[1]), 64) + int_to_hex(int(result_comm1[1].coeffs[0]), 64) + int_to_hex(int(result_comm1[1].coeffs[1]), 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64) + int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Name": "bls_g2add_p2+g2",
        "Expected": int_to_hex(int(result_comm2[0].coeffs[0]), 64) + int_to_hex(int(result_comm2[0].coeffs[1]), 64) + int_to_hex(int(result_comm2[1].coeffs[0]), 64) + int_to_hex(int(result_comm2[1].coeffs[1]), 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Name": "bls_g2add_(g2+0=g2)",
        "Expected": int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Name": "bls_g2add_(p2+0=p2)",
        "Expected": int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64) + int_to_hex(int(neg(G2)[0].coeffs[0]), 64) + int_to_hex(int(neg(G2)[0].coeffs[1]), 64) + int_to_hex(int(neg(G2)[1].coeffs[0]), 64) + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "Name": "bls_g2add_(g2-g2=0)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64) + int_to_hex(int(neg(P2)[0].coeffs[0]), 64) + int_to_hex(int(neg(P2)[0].coeffs[1]), 64) + int_to_hex(int(neg(P2)[1].coeffs[0]), 64) + int_to_hex(int(neg(P2)[1].coeffs[1]), 64),
        "Name": "bls_g2add_(p2-p2=0)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64) + int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Name": "bls_g2add_(g2+g2=2*g2)",
        "Expected": int_to_hex(int(result_doubling_G2[0].coeffs[0]), 64) + int_to_hex(int(result_doubling_G2[0].coeffs[1]), 64) + int_to_hex(int(result_doubling_G2[1].coeffs[0]), 64) + int_to_hex(int(result_doubling_G2[1].coeffs[1]), 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64) + int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64),
        "Name": "bls_g2add_(p2+p2=2*p2)",
        "Expected": int_to_hex(int(result_doubling_P2[0].coeffs[0]), 64) + int_to_hex(int(result_doubling_P2[0].coeffs[1]), 64) + int_to_hex(int(result_doubling_P2[1].coeffs[0]), 64) + int_to_hex(int(result_doubling_P2[1].coeffs[1]), 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        }
    ]


def case03_mul_G1():
    # Doubling
    result_doubling_G1 = add(G1, G1)
    assert result_doubling_G1 == multiply(G1, 2)
    result_doubling_P1 = add(P1, P1)
    assert result_doubling_P1 == multiply(P1, 2)

    yield 'mul_G1_bls', [
        {
        "Input": int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)) + int_to_hex(int(2), 32),
        "Name": "bls_g1mul_(g1+g1=2*g1)",
        "Expected": int_to_hex(int(result_doubling_G1[0]), 64) + (int_to_hex(int(result_doubling_G1[1]), 64)),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)) + int_to_hex(int(2), 32),
        "Name": "bls_g1mul_(p1+p1=2*p1)",
        "Expected": int_to_hex(int(result_doubling_P1[0]), 64) + (int_to_hex(int(result_doubling_P1[1]), 64)),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)) + int_to_hex(int(1), 32),
        "Name": "bls_g1mul_(1*g1=g1)",
        "Expected": int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)) + int_to_hex(int(1), 32),
        "Name": "bls_g1mul_(1*p1=p1)",
        "Expected": int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)) + int_to_hex(int(0), 32),
        "Name": "bls_g1mul_(0*g1=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)) + int_to_hex(int(0), 32),
        "Name": "bls_g1mul_(0*p1=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(int(17), 32),
        "Name": "bls_g1mul_(x*inf=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        }
    ]


def case04_mul_G2():
    # Doubling
    result_doubling_G2 = add(G2, G2)
    assert result_doubling_G2 == multiply(G2, 2)
    result_doubling_P2 = add(P2, P2)
    assert result_doubling_P2 == multiply(P2, 2)
    yield 'mul_G2_bls', [
        {
        "Input": int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64) + int_to_hex(int(2), 32),
        "Name": "bls_g2mul_(g2+g2=2*g2)",
        "Expected": int_to_hex(int(result_doubling_G2[0].coeffs[0]), 64) + int_to_hex(int(result_doubling_G2[0].coeffs[1]), 64) + int_to_hex(int(result_doubling_G2[1].coeffs[0]), 64) + int_to_hex(int(result_doubling_G2[1].coeffs[1]), 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64) + int_to_hex(int(2), 32),
        "Name": "bls_g2mul_(g2+g2=2*g2)",
        "Expected": int_to_hex(int(result_doubling_P2[0].coeffs[0]), 64) + int_to_hex(int(result_doubling_P2[0].coeffs[1]), 64) + int_to_hex(int(result_doubling_P2[1].coeffs[0]), 64) + int_to_hex(int(result_doubling_P2[1].coeffs[1]), 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64) + int_to_hex(int(1), 32),
        "Name": "bls_g2mul_(1*g2=g2)",
        "Expected": int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64) + int_to_hex(int(1), 32),
        "Name": "bls_g2mul_(1*p2=p2)",
        "Expected": int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64) + int_to_hex(int(0), 32),
        "Name": "bls_g2mul_(0*g2=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64) + int_to_hex(int(0), 32),
        "Name": "bls_g2mul_(0*p2=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(int(17), 32),
        "Name": "bls_g2mul_(x*inf=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        }
    ]


# Credit
# test vectors taken from
# https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/tree/master/poc/vectors
def case05_map_fp_to_G1():
    yield 'map_fp_to_G1_bls', [
    ]


# Credit
# test vectors taken from
# https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/tree/master/poc/vectors
def case07_hash_to_G2():
    for (msg, x_r, x_i, y_r, y_i) in HASH_G2_MESSAGES:
        point = hash_to_G2(msg, DST, H)
        # Affine
        result_x = point[0] / point[2]  # X / Z
        result_y = point[1] / point[2]  # Y / Z

        x = FQ2([hex_to_int(x_r), hex_to_int(x_i)])
        y = FQ2([hex_to_int(y_r), hex_to_int(y_i)])

        assert x == result_x
        assert y == result_y

        identifier = f'{encode_hex(msg)}'

        yield f'hash_to_G2__{(hash(bytes(identifier, "utf-8"))[:8]).hex()}', {
            'input': {
                'msg': msg.decode('utf-8')
            },
            'output': {
                'x': f'{x_r},{x_i}',
                'y': f'{y_r},{y_i}'
            }
        }


test_kinds: Dict[str, Generator[Tuple[str, Any], None, None]] = {
    'add_G1': case01_add_G1,
    'add_G2': case02_add_G2,
    'mul_G1': case03_mul_G1,
    'mul_G2': case04_mul_G2,
    'map_fp_to_G1': case05_map_fp_to_G1
}


def validate_output_dir(path_str):
    path = Path(path_str)

    if not path.exists():
        raise argparse.ArgumentTypeError("Output directory must exist")

    if not path.is_dir():
        raise argparse.ArgumentTypeError("Output path must lead to a directory")

    return path


def validate_encoding(encoding_str: str) -> Tuple[str, Callable[[Path, Any], None]]:
    encoding_str = encoding_str.lower()

    if encoding_str == "yaml" or encoding_str == "yml":
        yaml = YAML(pure=True)
        yaml.default_flow_style = None

        def _represent_none(self, _):
            return self.represent_scalar('tag:yaml.org,2002:null', 'null')

        yaml.representer.add_representer(type(None), _represent_none)

        def yaml_dumper(out_path: Path, data: Any) -> None:
            with out_path.open(file_mode) as f:
                yaml.dump(data, f)

        return ".yaml", yaml_dumper

    if encoding_str == "json":
        def json_dumper(out_path: Path, data: Any) -> None:
            with out_path.open(file_mode) as f:
                json.dump(data, f)

        return ".json", json_dumper

    raise argparse.ArgumentTypeError(f"Unrecognized encoding: {encoding_str}, expected 'json' or 'yaml'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="gen-bls",
        description="Generate BLS test vectors",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        dest="output_dir",
        required=True,
        type=validate_output_dir,
        help="directory into which the generated test vector files will be dumped"
    )
    parser.add_argument(
        "-e",
        "--encoding",
        dest="encoding",
        required=False,
        default='yaml',
        type=validate_encoding,
        help="encoding for output data"
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        default=False,
        help="if set re-generate and overwrite test files if they already exist",
    )

    args = parser.parse_args()

    output_dir = args.output_dir
    print(f"Generating tests into {output_dir}")

    if not args.force:
        file_mode = "x"
    else:
        file_mode = "w"

    extension, output_dumper = args.encoding

    for test_kind_name, test_kind_gen in test_kinds.items():
        test_dir = Path(output_dir) / Path('bls') / Path(test_kind_name)
        test_dir.mkdir(parents=True, exist_ok=True)

        for (case_name, case_content) in test_kind_gen():
            case_filepath = test_dir / Path(case_name + extension)

            if case_filepath.exists():
                if not args.force:
                    print(f'Skipping already existing test: {case_filepath}')
                    continue
                else:
                    print(
                        f'Warning, test case {case_filepath} already exists, test will be overwritten with new version')

            print(f'Generating test: {case_filepath}')

            # Lazy-evaluate test cases where necessary
            if callable(case_content):
                case_content = case_content()

            output_dumper(case_filepath, case_content)
