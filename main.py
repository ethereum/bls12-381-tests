"""
BLS test vectors generator
"""

from typing import Tuple, Any, Callable, Dict, Generator

import argparse
from pathlib import Path
import json
from ruamel.yaml import YAML

from hashlib import sha256

import milagro_bls_binding as milagro_bls

from py_ecc.bls import G2ProofOfPossession as bls

from py_ecc.bls.g2_primitives import (
    G1_to_pubkey,
)

from py_ecc.optimized_bls12_381 import (
    multiply,
    G1,
    FQ2,
)

from py_ecc.bls.hash_to_curve import hash_to_G2

from py_ecc.bls.hash import (
    os2ip,
)

from py_ecc.bls.point_compression import (
    decompress_G1,
    decompress_G2
)
from py_ecc.bls.typing import (
    G1Compressed,
    G2Compressed
)


def to_bytes32(i):
    return i.to_bytes(32, byteorder='big')


def hash(x):
    return sha256(x).digest()


def encode_hex(value: bytes) -> str:
    return "0x" + value.hex()


def int_to_big_endian(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')


def int_to_hex(n: int, byte_length: int = None) -> str:
    byte_value = int_to_big_endian(n)
    if byte_length:
        byte_value = byte_value.rjust(byte_length, b'\x00')
    return encode_hex(byte_value)


def hex_to_int(x: str) -> int:
    return int(x, 16)


MESSAGES = [
    bytes(b'\x00' * 32),
    bytes(b'\x56' * 32),
    bytes(b'\xab' * 32),
]
SAMPLE_MESSAGE = b'\x12' * 32

PRIVKEYS = [
    # Curve order is 256 so private keys are 32 bytes at most.
    # Also not all integers is a valid private key, so using pre-generated keys
    hex_to_int('0x00000000000000000000000000000000263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3'),
    hex_to_int('0x0000000000000000000000000000000047b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138'),
    hex_to_int('0x00000000000000000000000000000000328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216'),
]
PUBKEYS = [bls.SkToPk(privkey) for privkey in PRIVKEYS]

Z1_PUBKEY = b'\xc0' + b'\x00' * 47
NO_SIGNATURE = b'\x00' * 96
Z2_SIGNATURE = b'\xc0' + b'\x00' * 95
ZERO_PRIVKEY = 0
ZERO_PRIVKEY_BYTES = b'\x00' * 32

DST = b'QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_'
H = sha256
HASH_MESSAGES  =  [
    (b'',
    '0x0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a', '0x05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d',
    '0x0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92', '0x12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6'),
    (b'abc',
    '0x02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6', '0x139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8',
    '0x1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48', '0x00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16'),
    (b'abcdef0123456789',
    '0x121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0', '0x190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c',
    '0x05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8', '0x0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be'),
    (b'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '0x01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534', '0x11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569',
    '0x0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e', '0x03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52'),
]


def expect_exception(func, *args):
    try:
        func(*args)
    except Exception:
        pass
    else:
        raise Exception("should have raised exception")


def case01_sign():
    # Valid cases
    for privkey in PRIVKEYS:
        for message in MESSAGES:
            sig = bls.Sign(privkey, message)
            assert sig == milagro_bls.Sign(to_bytes32(privkey), message)  # double-check with milagro
            identifier = f'{int_to_hex(privkey)}_{encode_hex(message)}'
            yield f'sign_case_{(hash(bytes(identifier, "utf-8"))[:8]).hex()}', {
                'input': {
                    'privkey': int_to_hex(privkey),
                    'message': encode_hex(message),
                },
                'output': encode_hex(sig)
            }
    # Edge case: privkey == 0
    expect_exception(bls.Sign, ZERO_PRIVKEY, message)
    expect_exception(milagro_bls.Sign, ZERO_PRIVKEY_BYTES, message)
    yield f'sign_case_zero_privkey', {
        'input': {
            'privkey': encode_hex(ZERO_PRIVKEY_BYTES),
            'message': encode_hex(message),
        },
        'output': None
    }


def case02_verify():
    for i, privkey in enumerate(PRIVKEYS):
        for message in MESSAGES:
            # Valid signature
            signature = bls.Sign(privkey, message)
            pubkey = bls.SkToPk(privkey)

            assert milagro_bls.SkToPk(to_bytes32(privkey)) == pubkey
            assert milagro_bls.Sign(to_bytes32(privkey), message) == signature

            identifier = f'{encode_hex(pubkey)}_{encode_hex(message)}'

            assert bls.Verify(pubkey, message, signature)
            assert milagro_bls.Verify(pubkey, message, signature)

            yield f'verify_valid_case_{(hash(bytes(identifier, "utf-8"))[:8]).hex()}', {
                'input': {
                    'pubkey': encode_hex(pubkey),
                    'message': encode_hex(message),
                    'signature': encode_hex(signature),
                },
                'output': True,
            }

            # Invalid signatures -- wrong pubkey
            wrong_pubkey = bls.SkToPk(PRIVKEYS[(i + 1) % len(PRIVKEYS)])
            identifier = f'{encode_hex(wrong_pubkey)}_{encode_hex(message)}'
            assert not bls.Verify(wrong_pubkey, message, signature)
            assert not milagro_bls.Verify(wrong_pubkey, message, signature)
            yield f'verify_wrong_pubkey_case_{(hash(bytes(identifier, "utf-8"))[:8]).hex()}', {
                'input': {
                    'pubkey': encode_hex(wrong_pubkey),
                    'message': encode_hex(message),
                    'signature': encode_hex(signature),
                },
                'output': False,
            }

            # Invalid signature -- tampered with signature
            tampered_signature = signature[:-4] + b'\xFF\xFF\xFF\xFF'
            identifier = f'{encode_hex(pubkey)}_{encode_hex(message)}'
            assert not bls.Verify(pubkey, message, tampered_signature)
            assert not milagro_bls.Verify(pubkey, message, tampered_signature)
            yield f'verify_tampered_signature_case_{(hash(bytes(identifier, "utf-8"))[:8]).hex()}', {
                'input': {
                    'pubkey': encode_hex(pubkey),
                    'message': encode_hex(message),
                    'signature': encode_hex(tampered_signature),
                },
                'output': False,
            }

    # Invalid pubkey and signature with the point at infinity
    assert not bls.Verify(Z1_PUBKEY, SAMPLE_MESSAGE, Z2_SIGNATURE)
    assert not milagro_bls.Verify(Z1_PUBKEY, SAMPLE_MESSAGE, Z2_SIGNATURE)
    yield f'verify_infinity_pubkey_and_infinity_signature', {
        'input': {
            'pubkey': encode_hex(Z1_PUBKEY),
            'message': encode_hex(SAMPLE_MESSAGE),
            'signature': encode_hex(Z2_SIGNATURE),
        },
        'output': False,
    }

    privkey = 1
    
    #Valid  Edge case: privkey == 1
    pubkey = G1_to_pubkey(multiply(G1, privkey))
    signature = bls.Sign(privkey, SAMPLE_MESSAGE)
    identifier = f'{encode_hex(pubkey)}_{encode_hex(message)}'
    assert bls.Verify(pubkey, SAMPLE_MESSAGE, signature)
    assert milagro_bls.Verify(pubkey, SAMPLE_MESSAGE, signature)
    yield f'verifycase_one_privkey_{(hash(bytes(identifier, "utf-8"))[:8]).hex()}', {
        'input': {
            'pubkey': encode_hex(pubkey),
            'message': encode_hex(SAMPLE_MESSAGE),
            'signature': encode_hex(signature),
        },
        'output': True,
    }



def case03_aggregate():
    for message in MESSAGES:
        sigs = [bls.Sign(privkey, message) for privkey in PRIVKEYS]
        aggregate_sig = bls.Aggregate(sigs)
        assert aggregate_sig == milagro_bls.Aggregate(sigs)
        yield f'aggregate_{encode_hex(message)}', {
            'input': [encode_hex(sig) for sig in sigs],
            'output': encode_hex(aggregate_sig),
        }

    # Invalid pubkeys -- len(pubkeys) == 0
    expect_exception(bls.Aggregate, [])
    # No signatures to aggregate. Follow IETF BLS spec, return `None` to represent INVALID.
    # https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.8
    yield f'aggregate_na_signatures', {
        'input': [],
        'output': None,
    }

    # Valid to aggregate G2 point at infinity
    aggregate_sig = bls.Aggregate([Z2_SIGNATURE])
    assert aggregate_sig == milagro_bls.Aggregate([Z2_SIGNATURE]) == Z2_SIGNATURE
    yield f'aggregate_infinity_signature', {
        'input': [encode_hex(Z2_SIGNATURE)],
        'output': encode_hex(aggregate_sig),
    }

    # Valid to aggregate single signature
    sig = bls.Sign(PRIVKEYS[0], MESSAGES[0])
    aggregate_sig = bls.Aggregate([sig])
    assert aggregate_sig == milagro_bls.Aggregate([sig]) == sig
    yield f'aggregate_single_signature', {
        'input': [encode_hex(sig)],
        'output': encode_hex(aggregate_sig),
    }


def case04_fast_aggregate_verify():
    for i, message in enumerate(MESSAGES):
        privkeys = PRIVKEYS[:i + 1]
        sigs = [bls.Sign(privkey, message) for privkey in privkeys]
        aggregate_signature = bls.Aggregate(sigs)
        pubkeys = [bls.SkToPk(privkey) for privkey in privkeys]
        pubkeys_serial = [encode_hex(pubkey) for pubkey in pubkeys]

        # Valid signature
        identifier = f'{pubkeys_serial}_{encode_hex(message)}'
        assert bls.FastAggregateVerify(pubkeys, message, aggregate_signature)
        assert milagro_bls.FastAggregateVerify(pubkeys, message, aggregate_signature)
        yield f'fast_aggregate_verify_valid_{(hash(bytes(identifier, "utf-8"))[:8]).hex()}', {
            'input': {
                'pubkeys': pubkeys_serial,
                'message': encode_hex(message),
                'signature': encode_hex(aggregate_signature),
            },
            'output': True,
        }

        # Invalid signature -- extra pubkey
        pubkeys_extra = pubkeys + [bls.SkToPk(PRIVKEYS[-1])]
        pubkeys_extra_serial = [encode_hex(pubkey) for pubkey in pubkeys_extra]
        identifier = f'{pubkeys_extra_serial}_{encode_hex(message)}'
        assert not bls.FastAggregateVerify(pubkeys_extra, message, aggregate_signature)
        assert not milagro_bls.FastAggregateVerify(pubkeys_extra, message, aggregate_signature)
        yield f'fast_aggregate_verify_extra_pubkey_{(hash(bytes(identifier, "utf-8"))[:8]).hex()}', {
            'input': {
                'pubkeys': pubkeys_extra_serial,
                'message': encode_hex(message),
                'signature': encode_hex(aggregate_signature),
            },
            'output': False,
        }

        # Invalid signature -- tampered with signature
        tampered_signature = aggregate_signature[:-4] + b'\xff\xff\xff\xff'
        identifier = f'{pubkeys_serial}_{encode_hex(message)}'
        assert not bls.FastAggregateVerify(pubkeys, message, tampered_signature)
        assert not milagro_bls.FastAggregateVerify(pubkeys, message, tampered_signature)
        yield f'fast_aggregate_verify_tampered_signature_{(hash(bytes(identifier, "utf-8"))[:8]).hex()}', {
            'input': {
                'pubkeys': pubkeys_serial,
                'message': encode_hex(message),
                'signature': encode_hex(tampered_signature),
            },
            'output': False,
        }

    # Invalid pubkeys and signature -- len(pubkeys) == 0 and signature == Z1_SIGNATURE
    assert not bls.FastAggregateVerify([], message, Z2_SIGNATURE)
    assert not milagro_bls.FastAggregateVerify([], message, Z2_SIGNATURE)
    yield f'fast_aggregate_verify_na_pubkeys_and_infinity_signature', {
        'input': {
            'pubkeys': [],
            'message': encode_hex(message),
            'signature': encode_hex(Z2_SIGNATURE),
        },
        'output': False,
    }

    # Invalid pubkeys and signature -- len(pubkeys) == 0 and signature == 0x00...
    assert not bls.FastAggregateVerify([], message, NO_SIGNATURE)
    assert not milagro_bls.FastAggregateVerify([], message, NO_SIGNATURE)
    yield f'fast_aggregate_verify_na_pubkeys_and_na_signature', {
        'input': {
            'pubkeys': [],
            'message': encode_hex(message),
            'signature': encode_hex(NO_SIGNATURE),
        },
        'output': False,
    }

    # Invalid pubkeys and signature -- pubkeys contains point at infinity
    pubkeys = PUBKEYS.copy()
    pubkeys_with_infinity = pubkeys + [Z1_PUBKEY]
    signatures = [bls.Sign(privkey, SAMPLE_MESSAGE) for privkey in PRIVKEYS]
    aggregate_signature = bls.Aggregate(signatures)
    assert not bls.FastAggregateVerify(pubkeys_with_infinity, SAMPLE_MESSAGE, aggregate_signature)
    assert not milagro_bls.FastAggregateVerify(pubkeys_with_infinity, SAMPLE_MESSAGE, aggregate_signature)
    yield f'fast_aggregate_verify_infinity_pubkey', {
        'input': {
            'pubkeys': [encode_hex(pubkey) for pubkey in pubkeys_with_infinity],
            'message': encode_hex(SAMPLE_MESSAGE),
            'signature': encode_hex(aggregate_signature),
        },
        'output': False,
    }


def case05_aggregate_verify():
    pubkeys = []
    pubkeys_serial = []
    messages = []
    messages_serial = []
    sigs = []
    for privkey, message in zip(PRIVKEYS, MESSAGES):
        sig = bls.Sign(privkey, message)
        pubkey = bls.SkToPk(privkey)
        pubkeys.append(pubkey)
        pubkeys_serial.append(encode_hex(pubkey))
        messages.append(message)
        messages_serial.append(encode_hex(message))
        sigs.append(sig)

    aggregate_signature = bls.Aggregate(sigs)
    assert bls.AggregateVerify(pubkeys, messages, aggregate_signature)
    assert milagro_bls.AggregateVerify(pubkeys, messages, aggregate_signature)
    yield f'aggregate_verify_valid', {
        'input': {
            'pubkeys': pubkeys_serial,
            'messages': messages_serial,
            'signature': encode_hex(aggregate_signature),
        },
        'output': True,
    }

    tampered_signature = aggregate_signature[:4] + b'\xff\xff\xff\xff'
    assert not bls.AggregateVerify(pubkey, messages, tampered_signature)
    assert not milagro_bls.AggregateVerify(pubkeys, messages, tampered_signature)
    yield f'aggregate_verify_tampered_signature', {
        'input': {
            'pubkeys': pubkeys_serial,
            'messages': messages_serial,
            'signature': encode_hex(tampered_signature),
        },
        'output': False,
    }

    # Invalid pubkeys and signature -- len(pubkeys) == 0 and signature == Z1_SIGNATURE
    assert not bls.AggregateVerify([], [], Z2_SIGNATURE)
    assert not milagro_bls.AggregateVerify([], [], Z2_SIGNATURE)
    yield f'aggregate_verify_na_pubkeys_and_infinity_signature', {
        'input': {
            'pubkeys': [],
            'messages': [],
            'signature': encode_hex(Z2_SIGNATURE),
        },
        'output': False,
    }

    # Invalid pubkeys and signature -- len(pubkeys) == 0 and signature == 0x00...
    assert not bls.AggregateVerify([], [], NO_SIGNATURE)
    assert not milagro_bls.AggregateVerify([], [], NO_SIGNATURE)
    yield f'aggregate_verify_na_pubkeys_and_na_signature', {
        'input': {
            'pubkeys': [],
            'messages': [],
            'signature': encode_hex(NO_SIGNATURE),
        },
        'output': False,
    }

    # Invalid pubkeys and signature -- pubkeys contains point at infinity
    pubkeys_with_infinity = pubkeys + [Z1_PUBKEY]
    messages_with_sample = messages + [SAMPLE_MESSAGE]
    assert not bls.AggregateVerify(pubkeys_with_infinity, messages_with_sample, aggregate_signature)
    assert not milagro_bls.AggregateVerify(pubkeys_with_infinity, messages_with_sample, aggregate_signature)
    yield f'aggregate_verify_infinity_pubkey', {
        'input': {
            'pubkeys': [encode_hex(pubkey) for pubkey in pubkeys_with_infinity],
            'messages': [encode_hex(message) for message in messages_with_sample],
            'signature': encode_hex(aggregate_signature),
        },
        'output': False,
    }

def case06_hash_to_G2():
    for (msg,x_r,x_i,y_r,y_i) in HASH_MESSAGES:
        point = hash_to_G2(msg, DST, H)
        # Affine
        result_x = point[0] / point[2] # X / Z
        result_y = point[1] / point[2] # Y / Z

        x = FQ2([hex_to_int(x_r),hex_to_int(x_i)])
        y = FQ2([hex_to_int(y_r),hex_to_int(y_i)])

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

def case07_deserialization_G1():  

    pk = 'a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a'
    pk_for_wire = bytes.fromhex(pk)
    assert decompress_G1(G1Compressed(os2ip(pk_for_wire)))
    yield f'deserialization_succeeds_correct_point', {
        'input': {
            'pubkey': pk
        },
        'output': True,
    }

    pk = '8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    pk_for_wire = G1Compressed(os2ip(bytes.fromhex(pk)))
    # bug in py_ecc ?
    # TODO
    #expect_exception(decompress_G1,pk_for_wire)
    yield f'deserialization_fails_not_in_G1', {
        'input': {
            'pubkey': pk
        },
        'output': False,
    }

    pk = '8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0'
    pk_for_wire = G1Compressed(os2ip(bytes.fromhex(pk)))
    expect_exception(decompress_G1,pk_for_wire)
    yield f'deserialization_fails_not_in_curve', {
        'input': {
            'pubkey': pk
        },
        'output': False,
    }

    # Exactly the modulus, q
    pk = '9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab'
    pk_for_wire = G1Compressed(os2ip(bytes.fromhex(pk)))
    expect_exception(decompress_G1,pk_for_wire)
    yield f'deserialization_fails_x_equal_to_modulus', {
        'input': {
            'pubkey': pk
        },
        'output': False,
    }

    # One more than the modulus, q
    pk = '9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaac'
    pk_for_wire = G1Compressed(os2ip(bytes.fromhex(pk)))
    expect_exception(decompress_G1,pk_for_wire)
    yield f'deserialization_fails_x_greater_than_modulus', {
        'input': {
            'pubkey': pk
        },
        'output': False,
    }

    pk = '9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa'
    pk_for_wire = G1Compressed(os2ip(bytes.fromhex(pk)))
    expect_exception(decompress_G1,pk_for_wire)
    yield f'deserialization_fails_too_few_bytes', {
        'input': {
            'pubkey': pk
        },
        'output': False,
    }

    pk = '9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa900'
    pk_for_wire = G1Compressed(os2ip(bytes.fromhex(pk)))
    expect_exception(decompress_G1,pk_for_wire)
    yield f'deserialization_fails_too_many_bytes', {
        'input': {
            'pubkey': pk
        },
        'output': False,
    }

    pk = 'c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    pk_for_wire = bytes.fromhex(pk)
    assert decompress_G1(G1Compressed(os2ip(pk_for_wire)))
    yield f'deserialization_succeeds_infinity_with_true_b_flag', {
        'input': {
            'pubkey': pk
        },
        'output': True,
    }

    pk = '800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    pk_for_wire = G1Compressed(os2ip(bytes.fromhex(pk)))
    expect_exception(decompress_G1,pk_for_wire)
    yield f'deserialization_fails_infinity_with_false_b_flag', {
        'input': {
            'pubkey': pk
        },
        'output': False,
    }

    pk = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    pk_for_wire = G1Compressed(os2ip(bytes.fromhex(pk)))
    expect_exception(decompress_G1,pk_for_wire)
    yield f'deserialization_fails_with_wrong_c_flag', {
        'input': {
            'pubkey': pk
        },
        'output': False,
    }

    pk = 'c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    pk_for_wire = G1Compressed(os2ip(bytes.fromhex(pk)))
    expect_exception(decompress_G1,pk_for_wire)
    yield f'deserialization_fails_with_b_flag_and_x_nonzero', {
        'input': {
            'pubkey': pk
        },
        'output': False,
    }

    pk = 'e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    pk_for_wire = G1Compressed(os2ip(bytes.fromhex(pk)))
    expect_exception(decompress_G1,pk_for_wire)
    yield f'deserialization_fails_with_b_flag_and_a_flag_true', {
        'input': {
            'pubkey': pk
        },
        'output': False,
    }

def case08_deserialization_G2():

    sk = 'b2cc74bc9f089ed9764bbceac5edba416bef5e73701288977b9cac1ccb6964269d4ebf78b4e8aa7792ba09d3e49c8e6a1351bdf582971f796bbaf6320e81251c9d28f674d720cca07ed14596b96697cf18238e0e03ebd7fc1353d885a39407e0'
    sk_for_wire = bytes.fromhex(sk)
    assert decompress_G2(G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:]))))
    yield f'deserialization_succeeds_correct_point', {
        'input': {
            'pubkey': sk
        },
        'output': True,
    }
    
    # xRe is exactly the modulus, q, xIm is zero
    sk = '8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab'
    sk_for_wire = bytes.fromhex(sk)
    secretKey = G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:])))
    expect_exception(decompress_G2, secretKey)
    yield f'deserialization_fails_xre_equal_to_modulus', {
        'input': {
            'pubkey': sk
        },
        'output': False,
    }

    # xIm is exactly the modulus, q, xRe is zero
    sk = '9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    sk_for_wire = bytes.fromhex(sk)
    secretKey = G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:])))
    expect_exception(decompress_G2, secretKey)
    yield f'deserialization_fails_xim_equal_to_modulus', {
        'input': {
            'pubkey': sk
        },
        'output': False,
    }

    # xRe is the modulus plus 1, xIm is zero
    sk = '8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaac'    
    sk_for_wire = bytes.fromhex(sk)
    secretKey = G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:])))
    expect_exception(decompress_G2, secretKey)
    yield f'deserialization_fails_xre_greater_than_modulus', {
        'input': {
            'pubkey': sk
        },
        'output': False,
    }

    # xIm is the modulus plus 1, xRe is zero
    sk = '9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaac000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    sk_for_wire = bytes.fromhex(sk)
    secretKey = G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:])))
    # bug in py_ecc ?
    # TODO
    #expect_exception(decompress_G2, secretKey)
    yield f'deserialization_fails_xim_greater_than_modulus', {
        'input': {
            'pubkey': sk
        },
        'output': False,
    }

    sk = '8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    sk_for_wire = bytes.fromhex(sk)
    secretKey = G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:])))
    # fixed in https://github.com/ethereum/py_ecc/pull/121
    # TODO
    #expect_exception(decompress_G2, secretKey)
    yield f'deserialization_fails_not_in_G2', {
        'input': {
            'pubkey': sk
        },
        'output': False,
    }

    sk = '8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0'
    sk_for_wire = bytes.fromhex(sk)
    secretKey = G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:])))
    expect_exception(decompress_G2, secretKey)
    yield f'deserialization_fails_not_in_curve', {
        'input': {
            'pubkey': sk
        },
        'output': False,
    }

    sk = '8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd'
    sk_for_wire = bytes.fromhex(sk)
    secretKey = G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:])))
    expect_exception(decompress_G2, secretKey)
    yield f'deserialization_fails_too_few_bytes', {
        'input': {
            'pubkey': sk
        },
        'output': False,
    }

    sk = '8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefff'
    sk_for_wire = bytes.fromhex(sk)
    secretKey = G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:])))
    expect_exception(decompress_G2, secretKey)
    yield f'deserialization_fails_too_many_bytes', {
        'input': {
            'pubkey': sk
        },
        'output': False,
    }

    sk = 'c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    sk_for_wire = bytes.fromhex(sk)
    assert decompress_G2(G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:]))))
    yield f'deserialization_succeeds_infinity_with_true_b_flag', {
        'input': {
            'pubkey': sk
        },
        'output': True,
    }

    sk = '800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    sk_for_wire = bytes.fromhex(sk)
    secretKey = G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:])))
    expect_exception(decompress_G2, secretKey)
    yield f'deserialization_fails_infinity_with_false_b_flag', {
        'input': {
            'pubkey': sk
        },
        'output': False,
    }

    sk = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    sk_for_wire = bytes.fromhex(sk)
    secretKey = G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:])))
    expect_exception(decompress_G2, secretKey)
    yield f'deserialization_fails_with_wrong_c_flag', {
        'input': {
            'pubkey': sk
        },
        'output': False,
    }

    sk = 'c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    sk_for_wire = bytes.fromhex(sk)
    secretKey = G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:])))
    expect_exception(decompress_G2, secretKey)
    yield f'deserialization_fails_with_b_flag_and_x_nonzero', {
        'input': {
            'pubkey': sk
        },
        'output': False,
    }

    sk = 'e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    sk_for_wire = bytes.fromhex(sk)
    secretKey = G2Compressed((os2ip(sk_for_wire[:48]), os2ip(sk_for_wire[48:])))
    expect_exception(decompress_G2, secretKey)
    yield f'deserialization_fails_with_b_flag_and_a_flag_true', {
        'input': {
            'pubkey': sk
        },
        'output': False,
    }


test_kinds: Dict[str, Generator[Tuple[str, Any], None, None]] = {
    'sign': case01_sign,
    'verify': case02_verify,
    'aggregate': case03_aggregate,
    'fast_aggregate_verify': case04_fast_aggregate_verify,
    'aggregate_verify': case05_aggregate_verify,
    'hash_to_G2': case06_hash_to_G2,
    'deserialization_G1': case07_deserialization_G1,
    'deserialization_G2': case08_deserialization_G2,
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
        description=f"Generate BLS test vectors",
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
                    print(f'Warning, test case {case_filepath} already exists, test will be overwritten with new version')

            print(f'Generating test: {case_filepath}')

            # Lazy-evaluate test cases where necessary
            if callable(case_content):
                case_content = case_content()

            output_dumper(case_filepath, case_content)
