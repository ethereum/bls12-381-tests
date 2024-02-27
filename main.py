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
    add,
    multiply
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

BLS12_G1ADD_GAS = 500

MESSAGES = [
    bytes(b'\x00' * 32),
    bytes(b'\x56' * 32),
    bytes(b'\xab' * 32),
]
SAMPLE_MESSAGE = b'\x12' * 32

DST = b'QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_'
H = sha256
HASH_MESSAGES = [
    (b'',
     '0x0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a',
     '0x05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d',
     '0x0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92',
     '0x12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6'),
    (b'abc',
     '0x02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6',
     '0x139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8',
     '0x1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48',
     '0x00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16'),
    (b'abcdef0123456789',
     '0x121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0',
     '0x190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c',
     '0x05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8',
     '0x0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be'),
    (
    b'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '0x01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534',
    '0x11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569',
    '0x0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e',
    '0x03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52'),
]


def expect_exception(func, *args):
    try:
        func(*args)
    except Exception:
        pass
    else:
        raise Exception("should have raised exception")

def case01_add_G1():
        result = add(G1,G1)
        assert result == multiply(G1,2)
        yield f'add_G1_bls', [{
            "Input": int_to_hex(int(G1[0]),64)+(int_to_hex(int(G1[1]),64))+int_to_hex(int(G1[0]),64)+(int_to_hex(int(G1[1]),64)),
            "Name": "bls_g1add_(g1+g1=2*g1)",
            "Expected": int_to_hex(int(result[0]),64)+(int_to_hex(int(result[1]),64)),
            "Gas": BLS12_G1ADD_GAS,
            "NoBenchmark": False
        }]

# Credit
# test vectors taken from
# https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/tree/master/poc/vectors
def case07_hash_to_G2():
    for (msg, x_r, x_i, y_r, y_i) in HASH_MESSAGES:
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
