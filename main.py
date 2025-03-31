"""
BLS test vectors generator
"""

from typing import Tuple, Any, Callable, Dict, Generator

import argparse
from pathlib import Path
import json
from ruamel.yaml import YAML

from hashlib import sha256

from py_ecc.bls.hash import (
    os2ip,
)


from py_ecc.bls12_381 import (
    G1,
    G2,
    FQ,
    FQ2,
    add,
    multiply,
    neg,
    is_inf,
    field_modulus as q,
    curve_order
)


from py_ecc.bls.typing import (
    G1Compressed,
    G1Uncompressed,
    G2Compressed,
    G2Uncompressed
)


from py_ecc.bls.constants import (
    POW_2_381,
    POW_2_382,
    POW_2_383
)


from py_arkworks_bls12381 import (
    G1Point,
    G2Point,
    Scalar
)


from py_ecc.bls.point_compression import (
    decompress_G1,
    decompress_G2
)


def to_bytes32(i):
    return i.to_bytes(32, byteorder='big')


def hash(x):
    return sha256(x).digest()


def encode_hex(value: bytes) -> str:
    return value.hex()


def int_to_big_endian(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')


def int_to_little_endian(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder='little')


def int_to_hex(n: int, byte_length: int = None) -> str:
    byte_value = int_to_big_endian(n)
    if byte_length:
        byte_value = byte_value.rjust(byte_length, b'\x00')
    return encode_hex(byte_value)


def hex_to_int(x: str) -> int:
    return int(x, 16)


def compress_G1(pt: G1Uncompressed) -> G1Compressed:
    """
    A compressed point is a 384-bit integer with the bit order
    (c_flag, b_flag, a_flag, x), where the c_flag bit is always set to 1,
    the b_flag bit indicates infinity when set to 1,
    the a_flag bit helps determine the y-coordinate when decompressing,
    and the 381-bit integer x is the x-coordinate of the point.
    """
    if is_inf(pt):
        # Set c_flag = 1 and b_flag = 1. leave a_flag = x = 0
        return G1Compressed(POW_2_383 + POW_2_382)
    else:
        x, y = pt[0], pt[1]
        # Record y's leftmost bit to the a_flag
        a_flag = (y.n * 2) // q
        # Set c_flag = 1 and b_flag = 0
        return G1Compressed(x.n + a_flag * POW_2_381 + POW_2_383)


def compress_G2(pt: G2Uncompressed) -> G2Compressed:
    """
    The compressed point (z1, z2) has the bit order:
    z1: (c_flag1, b_flag1, a_flag1, x1)
    z2: (c_flag2, b_flag2, a_flag2, x2)
    where
    - c_flag1 is always set to 1
    - b_flag1 indicates infinity when set to 1
    - a_flag1 helps determine the y-coordinate when decompressing,
    - a_flag2, b_flag2, and c_flag2 are always set to 0
    """
    if is_inf(pt):
        return G2Compressed((POW_2_383 + POW_2_382, 0))
    x, y = pt[0], pt[1]
    x_re = int(x.coeffs[0])
    x_im = int(x.coeffs[1])
    y_re = int(y.coeffs[0])
    y_im = int(y.coeffs[1])
    # Record the leftmost bit of y_im to the a_flag1
    # If y_im happens to be zero, then use the bit of y_re
    a_flag1 = (y_im * 2) // q if y_im > 0 else (y_re * 2) // q

    # Imaginary part of x goes to z1, real part goes to z2
    # c_flag1 = 1, b_flag1 = 0
    z1 = x_im + a_flag1 * POW_2_381 + POW_2_383
    # a_flag2 = b_flag2 = c_flag2 = 0
    z2 = x_re
    return G2Compressed((z1, z2))


BLS12_G1ADD_GAS = 375
BLS12_G2ADD_GAS = 600
BLS12_G1MUL_GAS = 12000
BLS12_G2MUL_GAS = 22500
BLS12_MAP_FP_TO_G1_GAS = 5500
BLS12_MAP_FP2_TO_G2_GAS = 23800

# G1 MSM discount table as per EIP-2537
BLS12_G1_MULTIEXP_DISCOUNT_TABLE = [[1, 1000], [2, 949], [3, 848], [4, 797], [5, 764], [6, 750], [7, 738], [8, 728], [9, 719], [10, 712], [11, 705], [12, 698], [13, 692], [14, 687], [15, 682], [16, 677], [17, 673], [18, 669], [19, 665], [20, 661], [21, 658], [22, 654], [23, 651], [24, 648], [25, 645], [26, 642], [27, 640], [28, 637], [29, 635], [30, 632], [31, 630], [32, 627], [33, 625], [34, 623], [35, 621], [36, 619], [37, 617], [38, 615], [39, 613], [40, 611], [41, 609], [42, 608], [43, 606], [44, 604], [45, 603], [46, 601], [47, 599], [48, 598], [49, 596], [50, 595], [51, 593], [52, 592], [53, 591], [54, 589], [55, 588], [56, 586], [57, 585], [58, 584], [59, 582], [60, 581], [61, 580], [62, 579], [63, 577], [64, 576], [65, 575], [66, 574], [67, 573], [68, 572], [69, 570], [70, 569], [71, 568], [72, 567], [73, 566], [74, 565], [75, 564], [76, 563], [77, 562], [78, 561], [79, 560], [80, 559], [81, 558], [82, 557], [83, 556], [84, 555], [85, 554], [86, 553], [87, 552], [88, 551], [89, 550], [90, 549], [91, 548], [92, 547], [93, 547], [94, 546], [95, 545], [96, 544], [97, 543], [98, 542], [99, 541], [100, 540], [101, 540], [102, 539], [103, 538], [104, 537], [105, 536], [106, 536], [107, 535], [108, 534], [109, 533], [110, 532], [111, 532], [112, 531], [113, 530], [114, 529], [115, 528], [116, 528], [117, 527], [118, 526], [119, 525], [120, 525], [121, 524], [122, 523], [123, 522], [124, 522], [125, 521], [126, 520], [127, 520], [128, 519]]
BLS12_G1_MULTIEXP_MAX_DISCOUNT = 519

# G2 MSM discount table as per EIP-2537
BLS12_G2_MULTIEXP_DISCOUNT_TABLE = [[1, 1000], [2, 1000], [3, 923], [4, 884], [5, 855], [6, 832], [7, 812], [8, 796], [9, 782], [10, 770], [11, 759], [12, 749], [13, 740], [14, 732], [15, 724], [16, 717], [17, 711], [18, 704], [19, 699], [20, 693], [21, 688], [22, 683], [23, 679], [24, 674], [25, 670], [26, 666], [27, 663], [28, 659], [29, 655], [30, 652], [31, 649], [32, 646], [33, 643], [34, 640], [35, 637], [36, 634], [37, 632], [38, 629], [39, 627], [40, 624], [41, 622], [42, 620], [43, 618], [44, 615], [45, 613], [46, 611], [47, 609], [48, 607], [49, 606], [50, 604], [51, 602], [52, 600], [53, 598], [54, 597], [55, 595], [56, 593], [57, 592], [58, 590], [59, 589], [60, 587], [61, 586], [62, 584], [63, 583], [64, 582], [65, 580], [66, 579], [67, 578], [68, 576], [69, 575], [70, 574], [71, 573], [72, 571], [73, 570], [74, 569], [75, 568], [76, 567], [77, 566], [78, 565], [79, 563], [80, 562], [81, 561], [82, 560], [83, 559], [84, 558], [85, 557], [86, 556], [87, 555], [88, 554], [89, 553], [90, 552], [91, 552], [92, 551], [93, 550], [94, 549], [95, 548], [96, 547], [97, 546], [98, 545], [99, 545], [100, 544], [101, 543], [102, 542], [103, 541], [104, 541], [105, 540], [106, 539], [107, 538], [108, 537], [109, 537], [110, 536], [111, 535], [112, 535], [113, 534], [114, 533], [115, 532], [116, 532], [117, 531], [118, 530], [119, 530], [120, 529], [121, 528], [122, 528], [123, 527], [124, 526], [125, 526], [126, 525], [127, 524], [128, 524]]
BLS12_G2_MULTIEXP_MAX_DISCOUNT = 524

# Pairing check gas cost as per EIP-2537
BLS12_PAIRING_VARIABLE = 32600
BLS12_PAIRING_CONSTANT = 37700


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


# Point not in subgroup
# (order 11 * 10177 * 859267 * 52437899 * 52435875175126190479447740508185965837690552500527637822603658699938581184513) for curve over FQ
G1_not_in_correct_subgroup = (
    FQ(175120027539531016442854006573889751122153014990298010045047409866982914293422983043097473453160715743839524736495),
    FQ(3886161143382294459707944199964771025143673781268592314417728386394555910678469538674068117321209145872489588747338)
)


# Point not in subgroup (order 13) for curve over FQ2
G2_not_in_correct_subgroup = (
    FQ2([
        3922397287649913227621058437622997108794641953057758105879357683864299671651819357275859520733535654147680406731276,
        3741137028670202333708729730342450399205516524855163427388600406129033394826520864962370018146369072778910602014330
    ]),
    FQ2([
        2318861511113254089730073927932992301121994664766687670497054556026428871746827995944986621318870599424754598753423,
        1139817624251523735913718360323397122746649955859850938514186251456988186435865415993431523202408255536265404879025
    ])
)

# Point in the correct subgroup but in the invalid curve
# (isomorphic curve y^2 = x^3 + 24)
G1_in_correct_subgroup_invalid_curve = (
    FQ(1563311815873081220285993675342141245310974220297818772030154712466505762317169118162528189777729008132203959344556),
    FQ(3236674100890915460738904118849163307977137634186030159846763358736164886129980111795846993376080270444574334963907)
)


# Point in the correct subgroup but in the invalid curve
# (isomorphic curve y^2 = x^3 +
# (4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559679*i
# +4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559679))
G2_in_correct_subgroup_invalid_curve = (
    FQ2([
        3260589230528518565152427752655275816224272421636337760570971660512682917312168367022920113321683608097873411948046,
        2682010315718998361906236801126389678955008036316860700009564378603125513214046636630765687237948267280392735402121
    ]),
    FQ2([
        3874506299606973203009679409496841802766716505215050707701829465035115765455866172400205473037925034091373033409956,
        1429176592344479491745874702409109050659748424161659281885403188155138940704965631008642299070913936605324262095503
    ])
)


PRIVKEYS = [
    hex_to_int('0x00000000000000000000000000000000263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3'),
    hex_to_int('0x0000000000000000000000000000000047b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138'),
    hex_to_int('0x00000000000000000000000000000000328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216'),
    hex_to_int('0x00000000000000000000000000000000263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e2'),
    hex_to_int('0x0000000000000000000000000000000047b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665131'),
    hex_to_int('0x00000000000000000000000000000000328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d211'),
    hex_to_int('0x0000000000000000000000000000000055b53c4669f19f0fc7431929bc0363d7d8fb432435fcde2635fdba334424e9f5')
]


HASH_G1_MESSAGES = [
    (b'',
     '00000000000000000000000000000000156c8a6a2c184569d69a76be144b5cdc5141d2d2ca4fe341f011e25e3969c55ad9e9b9ce2eb833c81a908e5fa4ac5f03',
     '00000000000000000000000000000000184bb665c37ff561a89ec2122dd343f20e0f4cbcaec84e3c3052ea81d1834e192c426074b02ed3dca4e7676ce4ce48ba',
     '0000000000000000000000000000000004407b8d35af4dacc809927071fc0405218f1401a6d15af775810e4e460064bcc9468beeba82fdc751be70476c888bf3'),
    (b'abc',
     '00000000000000000000000000000000147e1ed29f06e4c5079b9d14fc89d2820d32419b990c1c7bb7dbea2a36a045124b31ffbde7c99329c05c559af1c6cc82',
     '00000000000000000000000000000000009769f3ab59bfd551d53a5f846b9984c59b97d6842b20a2c565baa167945e3d026a3755b6345df8ec7e6acb6868ae6d',
     '000000000000000000000000000000001532c00cf61aa3d0ce3e5aa20c3b531a2abd2c770a790a2613818303c6b830ffc0ecf6c357af3317b9575c567f11cd2c'),
    (b'abcdef0123456789',
     '0000000000000000000000000000000004090815ad598a06897dd89bcda860f25837d54e897298ce31e6947378134d3761dc59a572154963e8c954919ecfa82d',
     '000000000000000000000000000000001974dbb8e6b5d20b84df7e625e2fbfecb2cdb5f77d5eae5fb2955e5ce7313cae8364bc2fff520a6c25619739c6bdcb6a',
     '0000000000000000000000000000000015f9897e11c6441eaa676de141c8d83c37aab8667173cbe1dfd6de74d11861b961dccebcd9d289ac633455dfcc7013a3'),
    (b'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
     '0000000000000000000000000000000008dccd088ca55b8bfbc96fb50bb25c592faa867a8bb78d4e94a8cc2c92306190244532e91feba2b7fed977e3c3bb5a1f',
     '000000000000000000000000000000000a7a047c4a8397b3446450642c2ac64d7239b61872c9ae7a59707a8f4f950f101e766afe58223b3bff3a19a7f754027c',
     '000000000000000000000000000000001383aebba1e4327ccff7cf9912bda0dbc77de048b71ef8c8a81111d71dc33c5e3aa6edee9cf6f5fe525d50cc50b77cc9'),
    (b'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
     '000000000000000000000000000000000dd824886d2123a96447f6c56e3a3fa992fbfefdba17b6673f9f630ff19e4d326529db37e1c1be43f905bf9202e0278d',
     '000000000000000000000000000000000e7a16a975904f131682edbb03d9560d3e48214c9986bd50417a77108d13dc957500edf96462a3d01e62dc6cd468ef11',
     '000000000000000000000000000000000ae89e677711d05c30a48d6d75e76ca9fb70fe06c6dd6ff988683d89ccde29ac7d46c53bb97a59b1901abf1db66052db')
]

HASH_G2_MESSAGES = [
    (b'',
     '0000000000000000000000000000000007355d25caf6e7f2f0cb2812ca0e513bd026ed09dda65b177500fa31714e09ea0ded3a078b526bed3307f804d4b93b04',
     '0000000000000000000000000000000002829ce3c021339ccb5caf3e187f6370e1e2a311dec9b75363117063ab2015603ff52c3d3b98f19c2f65575e99e8b78c',
     '0000000000000000000000000000000000e7f4568a82b4b7dc1f14c6aaa055edf51502319c723c4dc2688c7fe5944c213f510328082396515734b6612c4e7bb7',
     '00000000000000000000000000000000126b855e9e69b1f691f816e48ac6977664d24d99f8724868a184186469ddfd4617367e94527d4b74fc86413483afb35b',
     '000000000000000000000000000000000caead0fd7b6176c01436833c79d305c78be307da5f6af6c133c47311def6ff1e0babf57a0fb5539fce7ee12407b0a42',
     '000000000000000000000000000000001498aadcf7ae2b345243e281ae076df6de84455d766ab6fcdaad71fab60abb2e8b980a440043cd305db09d283c895e3d'),
    (b'abc',
     '00000000000000000000000000000000138879a9559e24cecee8697b8b4ad32cced053138ab913b99872772dc753a2967ed50aabc907937aefb2439ba06cc50c',
     '000000000000000000000000000000000a1ae7999ea9bab1dcc9ef8887a6cb6e8f1e22566015428d220b7eec90ffa70ad1f624018a9ad11e78d588bd3617f9f2',
     '00000000000000000000000000000000108ed59fd9fae381abfd1d6bce2fd2fa220990f0f837fa30e0f27914ed6e1454db0d1ee957b219f61da6ff8be0d6441f',
     '000000000000000000000000000000000296238ea82c6d4adb3c838ee3cb2346049c90b96d602d7bb1b469b905c9228be25c627bffee872def773d5b2a2eb57d',
     '00000000000000000000000000000000033f90f6057aadacae7963b0a0b379dd46750c1c94a6357c99b65f63b79e321ff50fe3053330911c56b6ceea08fee656',
     '00000000000000000000000000000000153606c417e59fb331b7ae6bce4fbf7c5190c33ce9402b5ebe2b70e44fca614f3f1382a3625ed5493843d0b0a652fc3f'),
    (b'abcdef0123456789',
     '0000000000000000000000000000000018c16fe362b7dbdfa102e42bdfd3e2f4e6191d479437a59db4eb716986bf08ee1f42634db66bde97d6c16bbfd342b3b8',
     '000000000000000000000000000000000e37812ce1b146d998d5f92bdd5ada2a31bfd63dfe18311aa91637b5f279dd045763166aa1615e46a50d8d8f475f184e',
     '00000000000000000000000000000000038af300ef34c7759a6caaa4e69363cafeed218a1f207e93b2c70d91a1263d375d6730bd6b6509dcac3ba5b567e85bf3',
     '000000000000000000000000000000000da75be60fb6aa0e9e3143e40c42796edf15685cafe0279afd2a67c3dff1c82341f17effd402e4f1af240ea90f4b659b',
     '0000000000000000000000000000000019b148cbdf163cf0894f29660d2e7bfb2b68e37d54cc83fd4e6e62c020eaa48709302ef8e746736c0e19342cc1ce3df4',
     '000000000000000000000000000000000492f4fed741b073e5a82580f7c663f9b79e036b70ab3e51162359cec4e77c78086fe879b65ca7a47d34374c8315ac5e'),
    (b'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
     '0000000000000000000000000000000008d4a0997b9d52fecf99427abb721f0fa779479963315fe21c6445250de7183e3f63bfdf86570da8929489e421d4ee95',
     '0000000000000000000000000000000016cb4ccad91ec95aab070f22043916cd6a59c4ca94097f7f510043d48515526dc8eaaea27e586f09151ae613688d5a89',
     '000000000000000000000000000000000c5ae723be00e6c3f0efe184fdc0702b64588fe77dda152ab13099a3bacd3876767fa7bbad6d6fd90b3642e902b208f9',
     '0000000000000000000000000000000012c8c05c1d5fc7bfa847f4d7d81e294e66b9a78bc9953990c358945e1f042eedafce608b67fdd3ab0cb2e6e263b9b1ad',
     '0000000000000000000000000000000004e77ddb3ede41b5ec4396b7421dd916efc68a358a0d7425bddd253547f2fb4830522358491827265dfc5bcc1928a569',
     '0000000000000000000000000000000011c624c56dbe154d759d021eec60fab3d8b852395a89de497e48504366feedd4662d023af447d66926a28076813dd646'),
    (b'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
     '0000000000000000000000000000000003f80ce4ff0ca2f576d797a3660e3f65b274285c054feccc3215c879e2c0589d376e83ede13f93c32f05da0f68fd6a10',
     '00000000000000000000000000000000006488a837c5413746d868d1efb7232724da10eca410b07d8b505b9363bdccf0a1fc0029bad07d65b15ccfe6dd25e20d',
     '000000000000000000000000000000000ea4e7c33d43e17cc516a72f76437c4bf81d8f4eac69ac355d3bf9b71b8138d55dc10fd458be115afa798b55dac34be1',
     '000000000000000000000000000000001565c2f625032d232f13121d3cfb476f45275c303a037faa255f9da62000c2c864ea881e2bcddd111edc4a3c0da3e88d',
     '00000000000000000000000000000000043b6f5fe4e52c839148dc66f2b3751e69a0f6ebb3d056d6465d50d4108543ecd956e10fa1640dfd9bc0030cc2558d28',
     '000000000000000000000000000000000f8991d2a1ad662e7b6f58ab787947f1fa607fce12dde171bc17903b012091b657e15333e11701edcf5b63ba2a561247')
]


def case01_add_G1():
    # Commutativity
    result_comm1 = add(G1, P1)
    result_comm2 = add(P1, G1)
    assert result_comm1 == result_comm2
    result_add_not_in_correct_subgroup = add(G1_not_in_correct_subgroup, G1)
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
        "Input": ""
            # G1  point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64),
        "Name": "bls_g1add_g1+p1",
        "Expected": int_to_hex(int(result_comm1[0]), 64) + (int_to_hex(int(result_comm1[1]), 64)),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64),
        "Name": "bls_g1add_p1+g1",
        "Expected": int_to_hex(int(result_comm2[0]), 64) + (int_to_hex(int(result_comm2[1]), 64)),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point (not in correct subgroup)
            + int_to_hex(int(G1_not_in_correct_subgroup[0]), 64)
            + int_to_hex(int(G1_not_in_correct_subgroup[1]), 64)
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64),
        "Name": "bls_g1add_g1_not_in_correct_subgroup+g1",
        "Expected": int_to_hex(int(result_add_not_in_correct_subgroup[0]), 64) + (int_to_hex(int(result_add_not_in_correct_subgroup[1]), 64)),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # point at infinity
            + int_to_hex(0, 64)
            + int_to_hex(0, 64),
        "Name": "bls_g1add_(g1+0=g1)",
        "Expected": int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # point at infinity
            + int_to_hex(0, 64)
            + int_to_hex(0, 64),
        "Name": "bls_g1add_(p1+0=p1)",
        "Expected": int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # -G1 point
            + int_to_hex(int(neg(G1)[0]), 64)
            + int_to_hex(int(neg(G1)[1]), 64),
        "Name": "bls_g1add_(g1-g1=0)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # -P1 point
            + int_to_hex(int(neg(P1)[0]), 64)
            + int_to_hex(int(neg(P1)[1]), 64),
        "Name": "bls_g1add_(p1-p1=0)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64),
        "Name": "bls_g1add_(g1+g1=2*g1)",
        "Expected": int_to_hex(int(result_doubling_G1[0]), 64) + (int_to_hex(int(result_doubling_G1[1]), 64)),
        "Gas": BLS12_G1ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64),
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
    result_add_not_in_correct_subgroup = add(G2_not_in_correct_subgroup, G2)
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
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64),
        "Name": "bls_g2add_g2+p2",
        "Expected": int_to_hex(int(result_comm1[0].coeffs[0]), 64) + int_to_hex(int(result_comm1[0].coeffs[1]), 64) + int_to_hex(int(result_comm1[1].coeffs[0]), 64) + int_to_hex(int(result_comm1[1].coeffs[1]), 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Name": "bls_g2add_p2+g2",
        "Expected": int_to_hex(int(result_comm2[0].coeffs[0]), 64) + int_to_hex(int(result_comm2[0].coeffs[1]), 64) + int_to_hex(int(result_comm2[1].coeffs[0]), 64) + int_to_hex(int(result_comm2[1].coeffs[1]), 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point (not in correct subgroup)
            + int_to_hex(int(G2_not_in_correct_subgroup[0].coeffs[0]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[0].coeffs[1]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[1].coeffs[0]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[1].coeffs[1]), 64)
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Name": "bls_g2add_g2_not_in_correct_subgroup+g2",
        "Expected": int_to_hex(int(result_add_not_in_correct_subgroup[0].coeffs[0]), 64) + int_to_hex(int(result_add_not_in_correct_subgroup[0].coeffs[1]), 64) + int_to_hex(int(result_add_not_in_correct_subgroup[1].coeffs[0]), 64) + int_to_hex(int(result_add_not_in_correct_subgroup[1].coeffs[1]), 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # point at infinity
            + int_to_hex(0, 64) + int_to_hex(0, 64)
            + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Name": "bls_g2add_(g2+0=g2)",
        "Expected": int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # point at infinity
            + int_to_hex(0, 64) + int_to_hex(0, 64)
            + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Name": "bls_g2add_(p2+0=p2)",
        "Expected": int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # -G2 point
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "Name": "bls_g2add_(g2-g2=0)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # -P2 point
            + int_to_hex(int(neg(P2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(P2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(P2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(P2)[1].coeffs[1]), 64),
        "Name": "bls_g2add_(p2-p2=0)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Name": "bls_g2add_(g2+g2=2*g2)",
        "Expected": int_to_hex(int(result_doubling_G2[0].coeffs[0]), 64) + int_to_hex(int(result_doubling_G2[0].coeffs[1]), 64) + int_to_hex(
            int(result_doubling_G2[1].coeffs[0]), 64) + int_to_hex(int(result_doubling_G2[1].coeffs[1]), 64),
        "Gas": BLS12_G2ADD_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64),
        "Name": "bls_g2add_(p2+p2=2*p2)",
        "Expected": int_to_hex(int(result_doubling_P2[0].coeffs[0]), 64) + int_to_hex(int(result_doubling_P2[0].coeffs[1]), 64) + int_to_hex(
            int(result_doubling_P2[1].coeffs[0]), 64) + int_to_hex(int(result_doubling_P2[1].coeffs[1]), 64),
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

    result_multiply_G1 = multiply(G1, PRIVKEYS[0])
    result_multiply_P1 = multiply(P1, PRIVKEYS[0])

    yield 'mul_G1_bls', [
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # scalar 2
            + int_to_hex(int(2), 32),
        "Name": "bls_g1mul_(g1+g1=2*g1)",
        "Expected": int_to_hex(int(result_doubling_G1[0]), 64) + (int_to_hex(int(result_doubling_G1[1]), 64)),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # scalar 2
            + int_to_hex(int(2), 32),
        "Name": "bls_g1mul_(p1+p1=2*p1)",
        "Expected": int_to_hex(int(result_doubling_P1[0]), 64) + (int_to_hex(int(result_doubling_P1[1]), 64)),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # unity
            + int_to_hex(int(1), 32),
        "Name": "bls_g1mul_(1*g1=g1)",
        "Expected": int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # unity
            + int_to_hex(int(1), 32),
        "Name": "bls_g1mul_(1*p1=p1)",
        "Expected": int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # zero
            + int_to_hex(int(0), 32),
        "Name": "bls_g1mul_(0*g1=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # zero
            + int_to_hex(int(0), 32),
        "Name": "bls_g1mul_(0*p1=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # point at infinity
            + int_to_hex(0, 64)
            + int_to_hex(0, 64)
            # scalar
            + int_to_hex(int(17), 32),
        "Name": "bls_g1mul_(x*inf=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # random scalar
            + int_to_hex(PRIVKEYS[0], 32),
        "Name": "bls_g1mul_random*g1",
        "Expected": int_to_hex(int(result_multiply_G1[0]), 64) + (int_to_hex(int(result_multiply_G1[1]), 64)),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # random scalar
            + int_to_hex(PRIVKEYS[0], 32),
        "Name": "bls_g1mul_random*p1",
        "Expected": int_to_hex(int(result_multiply_P1[0]), 64) + (int_to_hex(int(result_multiply_P1[1]), 64)),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # random unnormalized scalar
            + int_to_hex(PRIVKEYS[0] + curve_order, 32),
        "Name": "bls_g1mul_random*g1_unnormalized_scalar",
        "Expected": int_to_hex(int(result_multiply_G1[0]), 64) + (int_to_hex(int(result_multiply_G1[1]), 64)),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # random unnormalized scalar
            + int_to_hex(PRIVKEYS[0] + curve_order, 32),
        "Name": "bls_g1mul_random*p1_unnormalized_scalar",
        "Expected": int_to_hex(int(result_multiply_P1[0]), 64) + (int_to_hex(int(result_multiply_P1[1]), 64)),
        "Gas": BLS12_G1MUL_GAS,
        "NoBenchmark": False
        },
    ]


def case04_mul_G2():
    # Doubling
    result_doubling_G2 = add(G2, G2)
    assert result_doubling_G2 == multiply(G2, 2)
    result_doubling_P2 = add(P2, P2)
    assert result_doubling_P2 == multiply(P2, 2)

    result_multiply_G2 = multiply(G2, PRIVKEYS[0])
    result_multiply_P2 = multiply(P2, PRIVKEYS[0])

    yield 'mul_G2_bls', [
        {
        "Input": ""
        # G2 point
        + int_to_hex(int(G2[0].coeffs[0]), 64)
        + int_to_hex(int(G2[0].coeffs[1]), 64)
        + int_to_hex(int(G2[1].coeffs[0]), 64)
        + int_to_hex(int(G2[1].coeffs[1]), 64)
        # scalar 2
        + int_to_hex(int(2), 32),
        "Name": "bls_g2mul_(g2+g2=2*g2)",
        "Expected": int_to_hex(int(result_doubling_G2[0].coeffs[0]), 64) + int_to_hex(int(result_doubling_G2[0].coeffs[1]), 64) + int_to_hex(
            int(result_doubling_G2[1].coeffs[0]), 64) + int_to_hex(int(result_doubling_G2[1].coeffs[1]), 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # scalar 2
            + int_to_hex(int(2), 32),
        "Name": "bls_g2mul_(p2+p2=2*p2)",
        "Expected": int_to_hex(int(result_doubling_P2[0].coeffs[0]), 64) + int_to_hex(int(result_doubling_P2[0].coeffs[1]), 64) + int_to_hex(
            int(result_doubling_P2[1].coeffs[0]), 64) + int_to_hex(int(result_doubling_P2[1].coeffs[1]), 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # unity
            + int_to_hex(int(1), 32),
        "Name": "bls_g2mul_(1*g2=g2)",
        "Expected": int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # unity
            + int_to_hex(int(1), 32),
        "Name": "bls_g2mul_(1*p2=p2)",
        "Expected": int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # zero
            + int_to_hex(int(0), 32),
        "Name": "bls_g2mul_(0*g2=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # zero
            + int_to_hex(int(0), 32),
        "Name": "bls_g2mul_(0*p2=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # point at infinity
            + int_to_hex(0, 64)
            + int_to_hex(0, 64)
            + int_to_hex(0, 64)
            + int_to_hex(0, 64)
            # scalar
            + int_to_hex(int(17), 32),
        "Name": "bls_g2mul_(x*inf=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # random scalar
            + int_to_hex(PRIVKEYS[0], 32),
        "Name": "bls_g2mul_random*g2",
        "Expected": int_to_hex(int(result_multiply_G2[0].coeffs[0]), 64) + int_to_hex(int(result_multiply_G2[0].coeffs[1]), 64) + int_to_hex(
            int(result_multiply_G2[1].coeffs[0]), 64) + int_to_hex(int(result_multiply_G2[1].coeffs[1]), 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # random scalar
            + int_to_hex(PRIVKEYS[0], 32),
        "Name": "bls_g2mul_random*p2",
        "Expected": int_to_hex(int(result_multiply_P2[0].coeffs[0]), 64) + int_to_hex(int(result_multiply_P2[0].coeffs[1]), 64) + int_to_hex(
            int(result_multiply_P2[1].coeffs[0]), 64) + int_to_hex(int(result_multiply_P2[1].coeffs[1]), 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # unnormalized scalar
            + int_to_hex(PRIVKEYS[0] + curve_order, 32),
        "Name": "bls_g2mul_random*g2_unnormalized_scalar",
        "Expected": int_to_hex(int(result_multiply_G2[0].coeffs[0]), 64) + int_to_hex(int(result_multiply_G2[0].coeffs[1]), 64) + int_to_hex(
            int(result_multiply_G2[1].coeffs[0]), 64) + int_to_hex(int(result_multiply_G2[1].coeffs[1]), 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # unnormalized scalar
            + int_to_hex(PRIVKEYS[0] + curve_order, 32),
        "Name": "bls_g2mul_random*p2_unnormalized_scalar",
        "Expected": int_to_hex(int(result_multiply_P2[0].coeffs[0]), 64) + int_to_hex(int(result_multiply_P2[0].coeffs[1]), 64) + int_to_hex(
            int(result_multiply_P2[1].coeffs[0]), 64) + int_to_hex(int(result_multiply_P2[1].coeffs[1]), 64),
        "Gas": BLS12_G2MUL_GAS,
        "NoBenchmark": False
        }
    ]


# Credit
# test vectors taken from
# https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/main/poc/vectors/BLS12381G1_XMD%3ASHA-256_SSWU_NU_.json
def case05_map_fp_to_G1():
    yield 'map_fp_to_G1_bls', [
        {
        "Input": HASH_G1_MESSAGES[0][1],
        "Name": "bls_g1map_" + encode_hex(HASH_G1_MESSAGES[0][0])[0:16],
        "Expected": HASH_G1_MESSAGES[0][2] + HASH_G1_MESSAGES[0][3],
        "Gas": BLS12_MAP_FP_TO_G1_GAS,
        "NoBenchmark": False
        },
        {
        "Input": HASH_G1_MESSAGES[1][1],
        "Name": "bls_g1map_" + encode_hex(HASH_G1_MESSAGES[1][0])[0:16],
        "Expected": HASH_G1_MESSAGES[1][2] + HASH_G1_MESSAGES[1][3],
        "Gas": BLS12_MAP_FP_TO_G1_GAS,
        "NoBenchmark": False
        },
        {
        "Input": HASH_G1_MESSAGES[2][1],
        "Name": "bls_g1map_" + encode_hex(HASH_G1_MESSAGES[2][0])[0:16],
        "Expected": HASH_G1_MESSAGES[2][2] + HASH_G1_MESSAGES[2][3],
        "Gas": BLS12_MAP_FP_TO_G1_GAS,
        "NoBenchmark": False
        },
        {
        "Input": HASH_G1_MESSAGES[3][1],
        "Name": "bls_g1map_" + encode_hex(HASH_G1_MESSAGES[3][0])[0:16],
        "Expected": HASH_G1_MESSAGES[3][2] + HASH_G1_MESSAGES[3][3],
        "Gas": BLS12_MAP_FP_TO_G1_GAS,
        "NoBenchmark": False
        },
        {
        "Input": HASH_G1_MESSAGES[4][1],
        "Name": "bls_g1map_" + encode_hex(HASH_G1_MESSAGES[4][0])[0:16],
        "Expected": HASH_G1_MESSAGES[4][2] + HASH_G1_MESSAGES[4][3],
        "Gas": BLS12_MAP_FP_TO_G1_GAS,
        "NoBenchmark": False
        }
    ]


# Credit
# test vectors taken from
# https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/main/poc/vectors/BLS12381G2_XMD%3ASHA-256_SSWU_NU_.json
def case06_map_fp2_to_G2():
    yield 'map_fp2_to_G2_bls', [
        {
        "Input": HASH_G2_MESSAGES[0][1] + HASH_G2_MESSAGES[0][2],
        "Name": "bls_g2map_" + encode_hex(HASH_G2_MESSAGES[0][0])[0:16],
        "Expected": HASH_G2_MESSAGES[0][3] + HASH_G2_MESSAGES[0][4] + HASH_G2_MESSAGES[0][5] + HASH_G2_MESSAGES[0][6],
        "Gas": BLS12_MAP_FP2_TO_G2_GAS,
        "NoBenchmark": False
        },
        {
        "Input": HASH_G2_MESSAGES[1][1] + HASH_G2_MESSAGES[1][2],
        "Name": "bls_g2map_" + encode_hex(HASH_G2_MESSAGES[1][0])[0:16],
        "Expected": HASH_G2_MESSAGES[1][3] + HASH_G2_MESSAGES[1][4] + HASH_G2_MESSAGES[1][5] + HASH_G2_MESSAGES[1][6],
        "Gas": BLS12_MAP_FP2_TO_G2_GAS,
        "NoBenchmark": False
        },
        {
        "Input": HASH_G2_MESSAGES[2][1] + HASH_G2_MESSAGES[2][2],
        "Name": "bls_g2map_" + encode_hex(HASH_G2_MESSAGES[2][0])[0:16],
        "Expected": HASH_G2_MESSAGES[2][3] + HASH_G2_MESSAGES[2][4] + HASH_G2_MESSAGES[2][5] + HASH_G2_MESSAGES[2][6],
        "Gas": BLS12_MAP_FP2_TO_G2_GAS,
        "NoBenchmark": False
        },
        {
        "Input": HASH_G2_MESSAGES[3][1] + HASH_G2_MESSAGES[3][2],
        "Name": "bls_g2map_" + encode_hex(HASH_G2_MESSAGES[3][0])[0:16],
        "Expected": HASH_G2_MESSAGES[3][3] + HASH_G2_MESSAGES[3][4] + HASH_G2_MESSAGES[3][5] + HASH_G2_MESSAGES[3][6],
        "Gas": BLS12_MAP_FP2_TO_G2_GAS,
        "NoBenchmark": False
        },
        {
        "Input": HASH_G2_MESSAGES[4][1] + HASH_G2_MESSAGES[4][2],
        "Name": "bls_g2map_" + encode_hex(HASH_G2_MESSAGES[4][0])[0:16],
        "Expected": HASH_G2_MESSAGES[4][3] + HASH_G2_MESSAGES[4][4] + HASH_G2_MESSAGES[4][5] + HASH_G2_MESSAGES[4][6],
        "Gas": BLS12_MAP_FP2_TO_G2_GAS,
        "NoBenchmark": False
        }
    ]


def case07_msm_G1():
    # Doubling
    result_doubling_G1 = add(G1, G1)
    assert result_doubling_G1 == multiply(G1, 2)
    result_doubling_P1 = add(P1, P1)
    assert result_doubling_P1 == multiply(P1, 2)
    g1s = [G1Point(), G1Point.from_compressed_bytes(bytes.fromhex(int_to_hex(compress_G1(P1))))]
    scalars = [Scalar(2), Scalar(2)]
    doubleP1G1 = decompress_G1(G1Compressed(os2ip(bytes.fromhex(str(G1Point.multiexp_unchecked(g1s, scalars))))))
    H1 = (FQ(hex_to_int(HASH_G1_MESSAGES[0][2])), FQ(hex_to_int(HASH_G1_MESSAGES[0][3])))
    H2 = (FQ(hex_to_int(HASH_G1_MESSAGES[1][2])), FQ(hex_to_int(HASH_G1_MESSAGES[1][3])))
    H3 = (FQ(hex_to_int(HASH_G1_MESSAGES[2][2])), FQ(hex_to_int(HASH_G1_MESSAGES[2][3])))
    H4 = (FQ(hex_to_int(HASH_G1_MESSAGES[3][2])), FQ(hex_to_int(HASH_G1_MESSAGES[3][3])))
    H5 = (FQ(hex_to_int(HASH_G1_MESSAGES[4][2])), FQ(hex_to_int(HASH_G1_MESSAGES[4][3])))
    g1s = [G1Point(), G1Point.from_compressed_bytes(bytes.fromhex(int_to_hex(compress_G1(P1)))), G1Point.from_compressed_bytes(
        bytes.fromhex(int_to_hex(compress_G1(H1)))), G1Point.from_compressed_bytes(
        bytes.fromhex(int_to_hex(compress_G1(H2)))), G1Point.from_compressed_bytes(
        bytes.fromhex(int_to_hex(compress_G1(H3)))), G1Point.from_compressed_bytes(
        bytes.fromhex(int_to_hex(compress_G1(H4)))), G1Point.from_compressed_bytes(
        bytes.fromhex(int_to_hex(compress_G1(H5))))]
    scalars = [Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[0])),
               Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[1])),
               Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[2])),
               Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[3])),
               Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[4])),
               Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[5])),
               Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[6]))]
    g1multiexp = decompress_G1(G1Compressed(os2ip(bytes.fromhex(str(G1Point.multiexp_unchecked(g1s, scalars))))))
    result_multiply_G1 = multiply(G1, PRIVKEYS[0])
    result_multiply_P1 = multiply(P1, PRIVKEYS[0])

    def discount_table_lookup(count):
        try:
            return BLS12_G1_MULTIEXP_DISCOUNT_TABLE[count - 1][1]
        except IndexError:
            return BLS12_G1_MULTIEXP_MAX_DISCOUNT

    yield 'msm_G1_bls', [
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # scalarr 2
            + int_to_hex(int(2), 32),
        "Name": "bls_g1msm_(g1+g1=2*g1)",
        "Expected": int_to_hex(int(result_doubling_G1[0]), 64) + (int_to_hex(int(result_doubling_G1[1]), 64)),
        "Gas": int((1 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # scalarr 2
            + int_to_hex(int(2), 32),
        "Name": "bls_g1msm_(p1+p1=2*p1)",
        "Expected": int_to_hex(int(result_doubling_P1[0]), 64) + (int_to_hex(int(result_doubling_P1[1]), 64)),
        "Gas": int((1 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # unity
            + int_to_hex(int(1), 32),
        "Name": "bls_g1msm_(1*g1=g1)",
        "Expected": int_to_hex(int(G1[0]), 64) + (int_to_hex(int(G1[1]), 64)),
        "Gas": int((1 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # unity
            + int_to_hex(int(1), 32),
        "Name": "bls_g1msm_(1*p1=p1)",
        "Expected": int_to_hex(int(P1[0]), 64) + (int_to_hex(int(P1[1]), 64)),
        "Gas": int((1 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # zero
            + int_to_hex(int(0), 32),
        "Name": "bls_g1msm_(0*g1=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": int((1 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # zero
            + int_to_hex(int(0), 32),
        "Name": "bls_g1msm_(0*p1=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": int((1 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # point at infinity
            + int_to_hex(0, 64)
            + int_to_hex(0, 64)
            # rscalar
            + int_to_hex(int(17), 32),
        "Name": "bls_g1msm_(x*inf=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": int((1 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32)
            # point at infinity
            + int_to_hex(0, 64)
            + int_to_hex(0, 64)
            # scalar
            + int_to_hex(int(2), 32),
        "Name": "bls_g1msm_(2g1+inf)",
        "Expected": int_to_hex(int(result_doubling_G1[0]), 64) + (int_to_hex(int(result_doubling_G1[1]), 64)),
        "Gas": int((2 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[1][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # zero
            + int_to_hex(int(0), 32)
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # zero
            + int_to_hex(int(0), 32),
        "Name": "bls_g1msm_(inf+inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": int((2 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[1][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
        # G1 point
        + int_to_hex(int(G1[0]), 64)
        + int_to_hex(int(G1[1]), 64)
        # scalar
        + int_to_hex(int(2), 32)
        # P1 point
        + int_to_hex(int(P1[0]), 64)
        + int_to_hex(int(P1[1]), 64)
        # scalar
        + int_to_hex(int(2), 32),
        "Name": "bls_g1msm_(2g1+2p1)",
        "Expected": int_to_hex(int(doubleP1G1[0]), 64) + (int_to_hex(int(doubleP1G1[1]), 64)),
        "Gas": int((2 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[1][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[0], 32)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[1], 32)
            # H1 point
            + int_to_hex(int(H1[0]), 64)
            + int_to_hex(int(H1[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[2], 32)
            # H2 point
            + int_to_hex(int(H2[0]), 64)
            + int_to_hex(int(H2[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[3], 32)
            # H3 point
            + int_to_hex(int(H3[0]), 64)
            + int_to_hex(int(H3[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[4], 32)
            # H4 point
            + int_to_hex(int(H4[0]), 64)
            + int_to_hex(int(H4[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[5], 32)
            # H5 point
            + int_to_hex(int(H5[0]), 64)
            + int_to_hex(int(H5[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[6], 32),
        "Name": "bls_g1msm_multiple",
        "Expected": int_to_hex(int(g1multiexp[0]), 64) + (int_to_hex(int(g1multiexp[1]), 64)),
        "Gas": int((7 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[6][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # unnormalized scalar
            + int_to_hex(PRIVKEYS[0] + curve_order, 32),
        "Name": "bls_g1msm_random*g1_unnormalized_scalar",
        "Expected": int_to_hex(int(result_multiply_G1[0]), 64) + (int_to_hex(int(result_multiply_G1[1]), 64)),
        "Gas": int((1 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # unnormalized scalar
            + int_to_hex(PRIVKEYS[0] + curve_order, 32),
        "Name": "bls_g1msm_random*p1_unnormalized_scalar",
        "Expected": int_to_hex(int(result_multiply_P1[0]), 64) + (int_to_hex(int(result_multiply_P1[1]), 64)),
        "Gas": int((1 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[0], 32)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[1], 32)
            # H1 point
            + int_to_hex(int(H1[0]), 64)
            + int_to_hex(int(H1[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[2], 32)
            # H2 point
            + int_to_hex(int(H2[0]), 64)
            + int_to_hex(int(H2[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[3], 32)
            # H3point
            + int_to_hex(int(H3[0]), 64)
            + int_to_hex(int(H3[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[4], 32)
            # H4 point
            + int_to_hex(int(H4[0]), 64)
            + int_to_hex(int(H4[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[5], 32)
            # point at infinity
            + int_to_hex(0, 128)
            # scalar zero
            + int_to_hex(0, 32)
            # H5 point
            + int_to_hex(int(H5[0]), 64)
            + int_to_hex(int(H5[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[6], 32),
        "Name": "bls_g1msm_multiple_with_point_at_infinity",
        "Expected": int_to_hex(int(g1multiexp[0]), 64) + (int_to_hex(int(g1multiexp[1]), 64)),
        "Gas": int((8 * BLS12_G1MUL_GAS * BLS12_G1_MULTIEXP_DISCOUNT_TABLE[7][1]) / 1000),
        "NoBenchmark": False
        }
    ] + [
        {
        "Input": count * (int_to_hex(0, 128) + int_to_hex(0, 32)),
        "Name": f"bls_g1msm_discount_table_{count}",
        "Expected": int_to_hex(0, 128),
        "Gas": int((count * BLS12_G1MUL_GAS * discount_table_lookup(count)) / 1000),
        "NoBenchmark": False
        } for count in range(1, 150)
    ]


def case08_msm_G2():
    # Doubling
    result_doubling_G2 = add(G2, G2)
    assert result_doubling_G2 == multiply(G2, 2)
    result_doubling_P2 = add(P2, P2)
    assert result_doubling_P2 == multiply(P2, 2)
    g2s = [G2Point(), G2Point.from_compressed_bytes(bytes.fromhex(int_to_hex(compress_G2(P2)[0]) + int_to_hex(compress_G2(P2)[1])))]
    scalars = [Scalar(2), Scalar(2)]
    doubleP2G2Ark = bytes.fromhex(str(G2Point.multiexp_unchecked(g2s, scalars)))
    doubleP2G2 = decompress_G2(G2Compressed((os2ip(doubleP2G2Ark[:48]), os2ip(doubleP2G2Ark[48:]))))
    H2 = (FQ2([hex_to_int(HASH_G2_MESSAGES[1][3]), hex_to_int(HASH_G2_MESSAGES[1][4])]), FQ2([hex_to_int(HASH_G2_MESSAGES[1][5]), hex_to_int(HASH_G2_MESSAGES[1][6])]), )
    H3 = (FQ2([hex_to_int(HASH_G2_MESSAGES[2][3]), hex_to_int(HASH_G2_MESSAGES[2][4])]), FQ2([hex_to_int(HASH_G2_MESSAGES[2][5]), hex_to_int(HASH_G2_MESSAGES[2][6])]), )
    H4 = (FQ2([hex_to_int(HASH_G2_MESSAGES[3][3]), hex_to_int(HASH_G2_MESSAGES[3][4])]), FQ2([hex_to_int(HASH_G2_MESSAGES[3][5]), hex_to_int(HASH_G2_MESSAGES[3][6])]), )
    H5 = (FQ2([hex_to_int(HASH_G2_MESSAGES[4][3]), hex_to_int(HASH_G2_MESSAGES[4][4])]), FQ2([hex_to_int(HASH_G2_MESSAGES[4][5]), hex_to_int(HASH_G2_MESSAGES[4][6])]), )
    g2s = [G2Point(), G2Point.from_compressed_bytes(bytes.fromhex(int_to_hex(compress_G2(P2)[0]) + int_to_hex(compress_G2(P2)[1]))), G2Point.from_compressed_bytes(
        bytes.fromhex(int_to_hex(compress_G2(H2)[0]) + int_to_hex(compress_G2(H2)[1]))), G2Point.from_compressed_bytes(
        bytes.fromhex(int_to_hex(compress_G2(H3)[0]) + int_to_hex(compress_G2(H3)[1]))), G2Point.from_compressed_bytes(
        bytes.fromhex(int_to_hex(compress_G2(H4)[0]) + int_to_hex(compress_G2(H4)[1]))), G2Point.from_compressed_bytes(
        bytes.fromhex(int_to_hex(compress_G2(H5)[0]) + int_to_hex(compress_G2(H5)[1])))]
    scalars = [Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[0])),
               Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[1])),
               Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[2])),
               Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[3])),
               Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[4])),
               Scalar.from_le_bytes(int_to_little_endian(PRIVKEYS[5]))]
    g2multiexpArk = bytes.fromhex(str(G2Point.multiexp_unchecked(g2s, scalars)))
    g2multiex = decompress_G2(G2Compressed((os2ip(g2multiexpArk[:48]), os2ip(g2multiexpArk[48:]))))
    result_multiply_G2 = multiply(G2, PRIVKEYS[0])
    result_multiply_P2 = multiply(P2, PRIVKEYS[0])

    def discount_table_lookup(count):
        try:
            return BLS12_G2_MULTIEXP_DISCOUNT_TABLE[count - 1][1]
        except IndexError:
            return BLS12_G2_MULTIEXP_MAX_DISCOUNT

    yield 'msm_G2_bls', [
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "Name": "bls_g2msm_(g2+g2=2*g2)",
        "Expected": int_to_hex(int(result_doubling_G2[0].coeffs[0]), 64) + int_to_hex(int(result_doubling_G2[0].coeffs[1]), 64) + int_to_hex(
            int(result_doubling_G2[1].coeffs[0]), 64) + int_to_hex(int(result_doubling_G2[1].coeffs[1]), 64),
        "Gas": int((1 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "Name": "bls_g2msm_(p2+p2=2*p2)",
        "Expected": int_to_hex(int(result_doubling_P2[0].coeffs[0]), 64) + int_to_hex(int(result_doubling_P2[0].coeffs[1]), 64) + int_to_hex(
            int(result_doubling_P2[1].coeffs[0]), 64) + int_to_hex(int(result_doubling_P2[1].coeffs[1]), 64),
        "Gas": int((1 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # unity
            + int_to_hex(int(1), 32),
        "Name": "bls_g2msm_(1*g2=g2)",
        "Expected": int_to_hex(int(G2[0].coeffs[0]), 64) + int_to_hex(int(G2[0].coeffs[1]), 64) + int_to_hex(int(G2[1].coeffs[0]), 64) + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Gas": int((1 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # unity
            + int_to_hex(int(1), 32),
        "Name": "bls_g2msm_(1*p2=p2)",
        "Expected": int_to_hex(int(P2[0].coeffs[0]), 64) + int_to_hex(int(P2[0].coeffs[1]), 64) + int_to_hex(int(P2[1].coeffs[0]), 64) + int_to_hex(int(P2[1].coeffs[1]), 64),
        "Gas": int((1 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # scalar zero
            + int_to_hex(int(0), 32),
        "Name": "bls_g2msm_(0*g2=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": int((1 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # scalar zero
            + int_to_hex(int(0), 32),
        "Name": "bls_g2msm_(0*p2=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": int((1 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # point at infinity
            + int_to_hex(0, 64) + int_to_hex(0, 64)
            + int_to_hex(0, 64) + int_to_hex(0, 64)
            # scalar
            + int_to_hex(int(17), 32),
        "Name": "bls_g2msm_(x*inf=inf)",
        "Expected": int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64) + int_to_hex(0, 64),
        "Gas": int((1 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(int(2), 32)
            # point at infinity
            + int_to_hex(0, 256)
            # scalar
            + int_to_hex(int(2), 32),
        "Name": "bls_g2msm_(2g2+inf)",
        "Expected": int_to_hex(int(result_doubling_G2[0].coeffs[0]), 64) + int_to_hex(int(result_doubling_G2[0].coeffs[1]), 64) + int_to_hex(
            int(result_doubling_G2[1].coeffs[0]), 64) + int_to_hex(int(result_doubling_G2[1].coeffs[1]), 64),
        "Gas": int((2 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[1][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(int(2), 32)
            # point at infinity
            + int_to_hex(0, 256)
            # scalar
            + int_to_hex(int(2), 32),
        "Name": "bls_g2msm_(2p2+inf)",
        "Expected": int_to_hex(int(result_doubling_P2[0].coeffs[0]), 64) + int_to_hex(int(result_doubling_P2[0].coeffs[1]), 64) + int_to_hex(
            int(result_doubling_P2[1].coeffs[0]), 64) + int_to_hex(int(result_doubling_P2[1].coeffs[1]), 64),
        "Gas": int((2 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[1][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # scalar zero
            + int_to_hex(int(0), 32)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # scalar zero
            + int_to_hex(int(0), 32),
        "Name": "bls_g1msm_(inf+inf)",
        "Expected": int_to_hex(0, 128) + int_to_hex(0, 128),
        "Gas": int((2 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[1][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(int(2), 32)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "Name": "bls_g2msm_(2g2+2p2)",
        "Expected": int_to_hex(int(doubleP2G2[0].coeffs[0]), 64) + int_to_hex(int(doubleP2G2[0].coeffs[1]), 64) + int_to_hex(
            int(doubleP2G2[1].coeffs[0]), 64) + int_to_hex(int(doubleP2G2[1].coeffs[1]), 64),
        "Gas": int((2 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[1][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[0], 32)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[1], 32)
            # H2 point
            + int_to_hex(int(H2[0].coeffs[0]), 64)
            + int_to_hex(int(H2[0].coeffs[1]), 64)
            + int_to_hex(int(H2[1].coeffs[0]), 64)
            + int_to_hex(int(H2[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[2], 32)
            # H3 point
            + int_to_hex(int(H3[0].coeffs[0]), 64)
            + int_to_hex(int(H3[0].coeffs[1]), 64)
            + int_to_hex(int(H3[1].coeffs[0]), 64)
            + int_to_hex(int(H3[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[3], 32)
            # H4point
            + int_to_hex(int(H4[0].coeffs[0]), 64)
            + int_to_hex(int(H4[0].coeffs[1]), 64)
            + int_to_hex(int(H4[1].coeffs[0]), 64)
            + int_to_hex(int(H4[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[4], 32)
            # H5 point
            + int_to_hex(int(H5[0].coeffs[0]), 64)
            + int_to_hex(int(H5[0].coeffs[1]), 64)
            + int_to_hex(int(H5[1].coeffs[0]), 64)
            + int_to_hex(int(H5[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[5], 32),
        "Name": "bls_g2msm_multiple",
        "Expected": int_to_hex(int(g2multiex[0].coeffs[0]), 64) + int_to_hex(int(g2multiex[0].coeffs[1]), 64) + int_to_hex(
            int(g2multiex[1].coeffs[0]), 64) + int_to_hex(int(g2multiex[1].coeffs[1]), 64),
        "Gas": int((6 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[5][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # unnormalized scalar
            + int_to_hex(PRIVKEYS[0] + curve_order, 32),
        "Name": "bls_g2msm_random*g2_unnormalized_scalar",
        "Expected": int_to_hex(int(result_multiply_G2[0].coeffs[0]), 64) + int_to_hex(int(result_multiply_G2[0].coeffs[1]), 64) + int_to_hex(
            int(result_multiply_G2[1].coeffs[0]), 64) + int_to_hex(int(result_multiply_G2[1].coeffs[1]), 64),
        "Gas": int((1 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # unnormalized scalar
            + int_to_hex(PRIVKEYS[0] + curve_order, 32),
        "Name": "bls_g2msm_random*p2_unnormalized_scalar",
        "Expected": int_to_hex(int(result_multiply_P2[0].coeffs[0]), 64) + int_to_hex(int(result_multiply_P2[0].coeffs[1]), 64) + int_to_hex(
            int(result_multiply_P2[1].coeffs[0]), 64) + int_to_hex(int(result_multiply_P2[1].coeffs[1]), 64),
        "Gas": int((1 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[0][1]) / 1000),
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[0], 32)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[1], 32)
            # H2 point
            + int_to_hex(int(H2[0].coeffs[0]), 64)
            + int_to_hex(int(H2[0].coeffs[1]), 64)
            + int_to_hex(int(H2[1].coeffs[0]), 64)
            + int_to_hex(int(H2[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[2], 32)
            # H3 point
            + int_to_hex(int(H3[0].coeffs[0]), 64)
            + int_to_hex(int(H3[0].coeffs[1]), 64)
            + int_to_hex(int(H3[1].coeffs[0]), 64)
            + int_to_hex(int(H3[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[3], 32)
            # H4 point
            + int_to_hex(int(H4[0].coeffs[0]), 64)
            + int_to_hex(int(H4[0].coeffs[1]), 64)
            + int_to_hex(int(H4[1].coeffs[0]), 64)
            + int_to_hex(int(H4[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[4], 32)
            # point at infinity
            + int_to_hex(0, 256)
            # scalar zero
            + int_to_hex(0, 32)
            # H5 point
            + int_to_hex(int(H5[0].coeffs[0]), 64)
            + int_to_hex(int(H5[0].coeffs[1]), 64)
            + int_to_hex(int(H5[1].coeffs[0]), 64)
            + int_to_hex(int(H5[1].coeffs[1]), 64)
            # scalar
            + int_to_hex(PRIVKEYS[5], 32),
        "Name": "bls_g2msm_multiple_with_point_at_infinity",
        "Expected": int_to_hex(int(g2multiex[0].coeffs[0]), 64) + int_to_hex(int(g2multiex[0].coeffs[1]), 64) + int_to_hex(
            int(g2multiex[1].coeffs[0]), 64) + int_to_hex(int(g2multiex[1].coeffs[1]), 64),
        "Gas": int((7 * BLS12_G2MUL_GAS * BLS12_G2_MULTIEXP_DISCOUNT_TABLE[6][1]) / 1000),
        "NoBenchmark": False
        },
    ] + [
        {
        "Input": count * (int_to_hex(0, 256) + int_to_hex(0, 32)),
        "Name": f"bls_g2msm_discount_table_{count}",
        "Expected": int_to_hex(0, 256),
        "Gas": int((count * BLS12_G2MUL_GAS * discount_table_lookup(count)) / 1000),
        "NoBenchmark": False
        } for count in range(1, 150)
    ]


def case09_pairing_check():

    result_add = add(G1, P1)
    result_multiply_G1 = multiply(G1, PRIVKEYS[0])
    result_multiply_G2 = multiply(G2, PRIVKEYS[1])
    result_multiply_G1a = multiply(result_multiply_G1, PRIVKEYS[1])
    result_multiply_G2a = multiply(result_multiply_G2, PRIVKEYS[0])

    yield 'pairing_check_bls', [
        {
        "Input": ""
            # G1 point (point at infinity)
            + int_to_hex(0, 128)
            # G2 point (point at infinity)
            + int_to_hex(0, 256),
        "Name": "bls_pairing_e(0,0)",
        "Expected": int_to_hex(1, 32),
        "Gas": 1 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point 1 (point at infinity)
            + int_to_hex(0, 128)
            # G2 point 1 (point at infinity)
            + int_to_hex(0, 256)
            # G1 point 2 (point at infinity)
            + int_to_hex(0, 128)
            # G2 point 2 (point at infinity)
            + int_to_hex(0, 256),
        "Name": "bls_pairing_e(0,0)=e(0,0)",
        "Expected": int_to_hex(1, 32),
        "Gas": 2 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point (point at infinity)
            + int_to_hex(0, 128)
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Name": "bls_pairing_e(0,G2)",
        "Expected": int_to_hex(1, 32),
        "Gas": 1 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point (point at infinity)
            + int_to_hex(0, 256),
        "Name": "bls_pairing_e(G1,0)",
        "Expected": int_to_hex(1, 32),
        "Gas": 1 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point 1 (point at infinity)
            + int_to_hex(0, 128)
            # G2 point 1
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G1 point 2
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "Name": "bls_pairing_e(0,-G2)!=e(-G1,G2)",
        "Expected": int_to_hex(0, 32),
        "Gas": 2 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point 1
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1 (point at infinity)
            + int_to_hex(0, 256)
            # G1 point 2
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "Name": "bls_pairing_e(G1,0)!=e(-G1,G2)",
        "Expected": int_to_hex(0, 32),
        "Gas": 2 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point 1
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1 (point at infinity)
            + int_to_hex(0, 256)
            # G1 point 2 (point at infinity)
            + int_to_hex(0, 128)
            # G2 point 2
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Name": "bls_pairing_e(G1,0)=e(0,G2)",
        "Expected": int_to_hex(1, 32),
        "Gas": 2 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point 1
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Name": "bls_pairing_non-degeneracy_e(P,Q)!= 1",
        "Expected": int_to_hex(0, 32),
        "Gas": 1 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point 1
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # P1 point 2
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # G2 point 2
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # P1 + G1 point 3
            + int_to_hex(int(result_add[0]), 64)
            + int_to_hex(int(result_add[1]), 64)
            # -G2 point 3
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "Name": "bls_pairing_bilinearity_e(G1,G2)*e(P1,G2)*e(P1+G1,-G2)=1",
        "Expected": int_to_hex(1, 32),
        "Gas": 3 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point 1
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G1 point 2
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # -G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "Name": "bls_pairing_e(G1,G2)*e(G1,-G2)=1",
        "Expected": int_to_hex(1, 32),
        "Gas": 2 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # aG1 point 1
            + int_to_hex(int(result_multiply_G1[0]), 64)
            + int_to_hex(int(result_multiply_G1[1]), 64)
            # bG2 point 1
            + int_to_hex(int(result_multiply_G2[0].coeffs[0]), 64)
            + int_to_hex(int(result_multiply_G2[0].coeffs[1]), 64)
            + int_to_hex(int(result_multiply_G2[1].coeffs[0]), 64)
            + int_to_hex(int(result_multiply_G2[1].coeffs[1]), 64)
            # abG1 point 2
            + int_to_hex(int(result_multiply_G1a[0]), 64)
            + int_to_hex(int(result_multiply_G1a[1]), 64)
            # -G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "Name": "bls_pairing_e(aG1,bG2)=e(abG1,G2)",
        "Expected": int_to_hex(1, 32),
        "Gas": 2 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # aG1 point 1
            + int_to_hex(int(result_multiply_G1[0]), 64)
            + int_to_hex(int(result_multiply_G1[1]), 64)
            # bG2 point 1
            + int_to_hex(int(result_multiply_G2[0].coeffs[0]), 64)
            + int_to_hex(int(result_multiply_G2[0].coeffs[1]), 64)
            + int_to_hex(int(result_multiply_G2[1].coeffs[0]), 64)
            + int_to_hex(int(result_multiply_G2[1].coeffs[1]), 64)
            # -G1 point 2
            + int_to_hex(int(neg(G1)[0]), 64)
            + int_to_hex(int(neg(G1)[1]), 64)
            # abG2 point 2
            + int_to_hex(int(result_multiply_G2a[0].coeffs[0]), 64)
            + int_to_hex(int(result_multiply_G2a[0].coeffs[1]), 64)
            + int_to_hex(int(result_multiply_G2a[1].coeffs[0]), 64)
            + int_to_hex(int(result_multiply_G2a[1].coeffs[1]), 64),
        "Name": "bls_pairing_e(aG1,bG2)=e(G1,abG2)",
        "Expected": int_to_hex(1, 32),
        "Gas": 2 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # aG1 point 1
            + int_to_hex(int(result_multiply_G1[0]), 64)
            + int_to_hex(int(result_multiply_G1[1]), 64)
            # bG2 point 1
            + int_to_hex(int(result_multiply_G2[0].coeffs[0]), 64)
            + int_to_hex(int(result_multiply_G2[0].coeffs[1]), 64)
            + int_to_hex(int(result_multiply_G2[1].coeffs[0]), 64)
            + int_to_hex(int(result_multiply_G2[1].coeffs[1]), 64)
            # -G1 point 2
            + int_to_hex(int(neg(G1)[0]), 64)
            + int_to_hex(int(neg(G1)[1]), 64)
            # abG2 point 2
            + int_to_hex(int(result_multiply_G2a[0].coeffs[0]), 64)
            + int_to_hex(int(result_multiply_G2a[0].coeffs[1]), 64)
            + int_to_hex(int(result_multiply_G2a[1].coeffs[0]), 64)
            + int_to_hex(int(result_multiply_G2a[1].coeffs[1]), 64),
        "Name": "bls_pairing_e(aG1,bG2)=3De(G1,abG2)",
        "Expected": int_to_hex(1, 32),
        "Gas": 2 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point 1
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G1 point (point at infinity)
            + int_to_hex(0, 128)
            # G2 point (point at infinity)
            + int_to_hex(0, 256)
            # G1 point 3
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # -G2 point 3
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "Name": "bls_pairing_e(G1,G2)*e(0,0)*e(G1,-G2)=1",
        "Expected": int_to_hex(1, 32),
        "Gas": 3 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        },
        {
        "Input": ""
            # G1 point 1
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G1 point (point at infinity)
            + int_to_hex(0, 128)
            # G2 point (point at infinity)
            + int_to_hex(0, 256)
            # G1 point 3
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 3
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "Name": "bls_pairing_e(G1,G2)*e(0,0)*e(G1,G2)=0",
        "Expected": int_to_hex(0, 32),
        "Gas": 3 * BLS12_PAIRING_VARIABLE + BLS12_PAIRING_CONSTANT,
        "NoBenchmark": False
        }
    ]


def case10_fail_add_G1():
    yield 'fail-add_G1_bls', [
        {
        "Input": "",
        "ExpectedError": "invalid input length",
        "Name": "bls_g1add_empty_input"
        },
        {
        "Input": ""
            # G1 point (short x coordinate)
            + int_to_hex(int(G1[0]), 63)
            + int_to_hex(int(G1[1]), 64)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64),
        "ExpectedError": "invalid input length",
        "Name": "bls_g1add_short_input"
        },
        {
        "Input": ""
            # G1 point (long x coordinate)
            + int_to_hex(int(G1[0]), 65)
            + int_to_hex(int(G1[1]), 64)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64),
        "ExpectedError": "invalid input length",
        "Name": "bls_g1add_large_input"
        },
        {
        "Input": ""
            # G1 point (not on curve)
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_g1add_point_not_on_curve"
        },
        {
        "Input": ""
            # G1 point (wrong encoding)
            + int_to_hex(int(G1[0]) + q, 64)
            + (int_to_hex(int(G1[1]), 64))
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + (int_to_hex(int(P1[1]), 64)),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_g2add_invalid_field_element"
        },
        {
        # G1 point (wrong element top bytes)
        "Input": "10"
        + int_to_hex(int(G1[0]), 63)
        + int_to_hex(int(G1[1]), 64)
        # P1 point
        + int_to_hex(int(P1[0]), 64)
        + int_to_hex(int(P1[1]), 64),
        "ExpectedError": "invalid field element top bytes",
        "Name": "bls_g1add_violate_top_bytes"
        },
        {
        "Input": ""
            # G1 point (not in correct subgroup but invalid curve)
            + int_to_hex(int(G1_in_correct_subgroup_invalid_curve[0]), 64)
            + int_to_hex(int(G1_in_correct_subgroup_invalid_curve[1]), 64)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_g1add_point_in_correct_subgroup_invalid_curve"
        },
    ]


def case11_fail_add_G2():
    yield 'fail-add_G2_bls', [
        {
        "Input": "",
        "ExpectedError": "invalid input length",
        "Name": "bls_g2add_empty_input"
        },
        {
        "Input": ""
            # G2 point (short x coordinate)
            + int_to_hex(int(G2[0].coeffs[0]), 63)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64),
        "ExpectedError": "invalid input length",
        "Name": "bls_g2add_short_input"
        },
        {
        "Input": ""
            # G2 point (long x coordinate)
            + int_to_hex(int(G2[0].coeffs[0]), 65)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64),
        "ExpectedError": "invalid input length",
        "Name": "bls_g2add_long_input"
        },
        {
        "Input": ""
            # G2 point (not on curve)
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_g2add_point_not_on_curve"
        },
        {
        "Input": ""
            # G2 point (wrong encoding)
            + int_to_hex(int(G2[0].coeffs[0]) + q, 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_g2add_invalid_field_element"
        },
        {
        # G2 point (wrong element top bytes)
        "Input": "10"
            + int_to_hex(int(G2[0].coeffs[0]), 63)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64),
        "ExpectedError": "invalid field element top bytes",
        "Name": "bls_g2add_violate_top_bytes"
        }
    ]


def case12_fail_mul_G1():
    yield 'fail-mul_G1_bls', [
        {
        "Input": "",
        "ExpectedError": "invalid input length",
        "Name": "bls_g1mul_empty_input"
        },
        {
        "Input": ""
            # G1 point (short x coordinate)
            + int_to_hex(int(G1[0]), 63)
            + int_to_hex(int(G1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid input length",
        "Name": "bls_g1mul_short_input"
        },
        {
        "Input": ""
            # G1 point (long x coordinate)
            + int_to_hex(int(G1[0]), 65)
            + int_to_hex(int(G1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid input length",
        "Name": "bls_g1mul_large_input"
        },
        {
        "Input": ""
            # G1 point (wrong encoding)
            + int_to_hex(int(G1[0]) + q, 64)
            + int_to_hex(int(G1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_g1mul_invalid_field_element"
        },
        {
        "Input": ""
            # G1 point (not on curve)
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_g1mul_point_not_on_curve"
        },
        {
        # G1 point (wrong element top bytes)
        "Input": "10"
            + int_to_hex(int(G1[0]), 63)
            + int_to_hex(int(G1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid field element top bytes",
        "Name": "bls_g1mul_violate_top_bytes"
        },
        {
        "Input": ""
            # G1 point (not in the correct subgroup)
            + int_to_hex(int(G1_not_in_correct_subgroup[0]), 64)
            + int_to_hex(int(G1_not_in_correct_subgroup[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "g1 point is not in the correct subgroup",
        "Name": "bls_g1mul_g1_not_in_correct_subgroup"
        },
        {
        "Input": ""
            # G1 point (not in correct subgroup but invalid curve)
            + int_to_hex(int(G1_in_correct_subgroup_invalid_curve[0]), 64)
            + int_to_hex(int(G1_in_correct_subgroup_invalid_curve[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_g1mul_g1_in_correct_subgroup_invalid_curve"
        }
    ]


def case13_fail_mul_G2():
    yield 'fail-mul_G2_bls', [
        {
        "Input": "",
        "ExpectedError": "invalid input length",
        "Name": "bls_g2mul_empty_input"
        },
        {
        "Input": ""
            # G2 point (short x coordinate)
            + int_to_hex(int(G2[0].coeffs[0]), 63)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid input length",
        "Name": "bls_g2mul_short_input"
        },
        {
        "Input": ""
            # G2 point (long x coordinate)
            + int_to_hex(int(G2[0].coeffs[0]), 65)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid input length",
        "Name": "bls_g2mul_large_input"
        },
        {
        "Input": ""
            # G2 point (wrong encoding)
            + int_to_hex(int(G2[0].coeffs[0]) + q, 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_g2mul_invalid_field_element"
        },
        {
        "Input": ""
            # G2 point (not on curve)
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_g2mul_point_not_on_curve"
        },
        {
        # G2 point (wrong element top bytes)
        "Input": "10"
            + int_to_hex(int(G2[0].coeffs[0]), 63)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid field element top bytes",
        "Name": "bls_g2mul_violate_top_bytes"
        },
        {
        "Input": ""
            # G2 point (not in the correct subgroup)
            + int_to_hex(int(G2_not_in_correct_subgroup[0].coeffs[0]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[0].coeffs[1]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[1].coeffs[0]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "g2 point is not in the correct subgroup",
        "Name": "bls_g2mul_g2_not_in_correct_subgroup"
        },
        {
        "Input": ""
            # G2 point (not on curve)
            + int_to_hex(int(G2_in_correct_subgroup_invalid_curve[0].coeffs[0]), 64)
            + int_to_hex(int(G2_in_correct_subgroup_invalid_curve[0].coeffs[1]), 64)
            + int_to_hex(int(G2_in_correct_subgroup_invalid_curve[1].coeffs[0]), 64)
            + int_to_hex(int(G2_in_correct_subgroup_invalid_curve[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_g2mul_g2_in_correct_subgroup_invalid_curve"
        }
    ]


def case14_fail_map_fp_to_G1():
    yield 'fail-map_fp_to_G1_bls', [
        {
        "Input": "",
        "ExpectedError": "invalid input length",
        "Name": "bls_mapg1_empty_input"
        },
        {
        "Input": HASH_G1_MESSAGES[0][1][0:126],
        "ExpectedError": "invalid input length",
        "Name": "bls_mapg1_short_input"
        },
        {
        "Input": "00" + HASH_G1_MESSAGES[0][1],
        "ExpectedError": "invalid input length",
        "Name": "bls_mapg1_large_input"
        },
        {
        "Input": "10" + HASH_G1_MESSAGES[0][1][0:126],
        "ExpectedError": "invalid field element top bytes",
        "Name": "bls_mapg1_top_bytes"
        },
        {
        "Input": int_to_hex(hex_to_int(HASH_G1_MESSAGES[0][1]) + q, 64),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_invalid_fq_element"
        },
    ]


def case15_fail_map_fp2_to_G2():
    yield 'fail-map_fp2_to_G2_bls', [
        {
        "Input": "",
        "ExpectedError": "invalid input length",
        "Name": "bls_mapg2_empty_input"
        },
        {
        "Input": HASH_G2_MESSAGES[0][1] + HASH_G2_MESSAGES[0][2][0:126],
        "ExpectedError": "invalid input length",
        "Name": "bls_mapg2_short_input"
        },
        {
        "Input": "00" + HASH_G2_MESSAGES[0][1] + HASH_G2_MESSAGES[0][2],
        "ExpectedError": "invalid input length",
        "Name": "bls_mapg2_long_input"
        },
        {
        "Input": "00" + HASH_G2_MESSAGES[0][1] + HASH_G2_MESSAGES[0][2][0:126],
        "ExpectedError": "invalid field element top bytes",
        "Name": "bls_mapg2_top_bytes"
        },
        {
        "Input": int_to_hex(hex_to_int(HASH_G2_MESSAGES[0][1]) + q, 64) + HASH_G2_MESSAGES[0][2],
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_mapg2_invalid_fq_element"
        }
    ]


def case16_fail_msm_G1():
    yield 'fail-msm_G1_bls', [
        {
        "Input": "",
        "ExpectedError": "invalid input length",
        "Name": "bls_g1msm_empty_input"
        },
        {
        "Input": ""
            # G1 point (short x coordinate)
            + int_to_hex(int(G1[0]), 63)
            + int_to_hex(int(G1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid input length",
        "Name": "bls_g1msm_short_input"
        },
        {
        "Input": ""
            # G1 point (long x coordinate)
            + int_to_hex(int(G1[0]), 65)
            + int_to_hex(int(G1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid input length",
        "Name": "bls_g1msm_long_input"
        },
        {
        "Input": ""
            # G1 point (wrong encoding)
            + int_to_hex(int(G1[0]) + q, 64)
            + int_to_hex(int(G1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_g1msm_invalid_field_element"
        },
        {
        # G1 point (wrong element top bytes)
        "Input": "10"
        + int_to_hex(int(G1[0]), 63)
        + int_to_hex(int(G1[1]), 64)
        # scalar
        + int_to_hex(int(2), 32)
        # P1 point
        + int_to_hex(int(P1[0]), 64)
        + int_to_hex(int(P1[1]), 64)
        # scalar
        + int_to_hex(int(2), 32),
        "ExpectedError": "invalid field element top bytes",
        "Name": "bls_g1msm_violate_top_bytes"
        },
        {
        "Input": ""
            # G1 point (not on curve)
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_g1msm_point_not_on_curve"
        },
        {
        "Input": ""
            # G1 point (not in the correct subgroup)
            + int_to_hex(int(G1_not_in_correct_subgroup[0]), 64)
            + int_to_hex(int(G1_not_in_correct_subgroup[1]), 64)
            # scalar
            + int_to_hex(int(2), 32)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "g1 point is not in the correct subgroup",
        "Name": "bls_g1msm_g1_not_in_correct_subgroup"
        },
        {
        "Input": ""
            # G1 point (not in correct subgroup but invalid curve)
            + int_to_hex(int(G1_in_correct_subgroup_invalid_curve[0]), 64)
            + int_to_hex(int(G1_in_correct_subgroup_invalid_curve[1]), 64)
            # scalar
            + int_to_hex(int(2), 32)
            # P1 point
            + int_to_hex(int(P1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_g1msm_point_in_correct_subgroup_invalid_curve"
        }
    ]


def case17_fail_msm_G2():
    yield 'fail-msm_G2_bls', [
        {
        "Input": "",
        "ExpectedError": "invalid input length",
        "Name": "bls_g2msm_empty_input"
        },
        {
        "Input": ""
            # G2 point (short x coordinate)
            + int_to_hex(int(G2[0].coeffs[0]), 63)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid input length",
        "Name": "bls_g2msm_short_input"
        },
        {
        "Input": ""
            # G2 point (long x coordinate)
            + int_to_hex(int(G2[0].coeffs[0]), 65)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid input length",
        "Name": "bls_g2msm_long_input"
        },
        {
        # G2 point (wrong element top bytes)
        "Input": "10"
            + int_to_hex(int(G2[0].coeffs[0]), 63)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid field element top bytes",
        "Name": "bls_g2msm_violate_top_bytes"
        },
        {
        "Input": ""
            # G2 point (wrong encoding)
            + int_to_hex(int(G2[0].coeffs[0]) + q, 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_g2msm_invalid_field_element"
        },
        {
        "Input": ""
            # G2 point (not on curve)
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_g2msm_point_not_on_curve"
        },
        {
        "Input": ""
            # G2 point (not in the correct subgroup)
            + int_to_hex(int(G2_not_in_correct_subgroup[0].coeffs[0]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[0].coeffs[1]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[1].coeffs[0]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32)
            # P2 point
            + int_to_hex(int(P2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(P2[1].coeffs[0]), 64)
            + int_to_hex(int(P2[1].coeffs[1]), 64)
            #  scalar
            + int_to_hex(int(2), 32),
        "ExpectedError": "g2 point is not in the correct subgroup",
        "Name": "bls_pairing_g2_not_in_correct_subgroup"
        }
    ]


def case18_fail_pairing_check():
    yield 'fail-pairing_check_bls', [
        {
        "Input": "",
        "ExpectedError": "invalid input length",
        "Name": "bls_pairing_empty_input"
        },
        {
        "Input": ""
            # G1 point 1 (short x coordinate)
            + int_to_hex(int(G1[0]), 63)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G1 point 2
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "ExpectedError": "invalid input length",
        "Name": "bls_pairing_missing_data"
        },
        {
        "Input": ""
            # G1 point 1 (long x coordinate)
            + int_to_hex(int(G1[0]), 65)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G1 point 2
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "ExpectedError": "invalid input length",
        "Name": "bls_pairing_extra_data"
        },
        {
        # G1 point (wrong element top bytes)
        "Input": "10"
            + int_to_hex(int(G1[0]), 63)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G1 point 2
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "ExpectedError": "invalid field element top bytes",
        "Name": "bls_pairing_top_bytes"
        },
        {
        "Input": ""
            # G1 point (field element equal to modulus)
            + int_to_hex(q, 64)  # Set to modulus
            + int_to_hex(int(G1[1]), 64)
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_pairing_e(G1_field_element_equal_to_modulus,G2)"
        },
        {
        "Input": ""
            # G1 point (invalid field element)
            + int_to_hex(int(G1[0]) + q, 64)  # Plus Q
            + int_to_hex(int(G1[1]), 64)
            # G2 point (point at infinity)
            + int_to_hex(0, 256),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_pairing_e(G1_invalid_field_element,0)",
        },
        {
        "Input": ""
            # G1 point (point at infinity)
            + int_to_hex(0, 128)
            # G2 point (invalid field element)
            + int_to_hex(int(G2[0].coeffs[0]) + q, 64)  # Plus Q
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_pairing_e(0,G2_invalid_field_element)",
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]) + q, 64)  # Plus Q
            + int_to_hex(int(G1[1]), 64)
            # G2 point (invalid field element)
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_pairing_e(G1_invalid_field_element,G2)",
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point (invalid field element)
            + int_to_hex(int(G2[0].coeffs[0]) + q, 64)  # Plus Q
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_pairing_e(G1,G2_invalid_field_element)",
        },
        {
        "Input": ""
            # G1 point (wrong encoding)
            + int_to_hex(int(G1[0]) + q, 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G1 point 2
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_pairing_e(G1_invalid_field_element,-G2)=e(-G1,G2)",
        },
        {
        "Input": ""
            # G1 point 1
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G1 point 1
            + int_to_hex(int(G2[0].coeffs[0]) + q, 64)  # Plus Q
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G1 point 2
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "ExpectedError": "invalid fp.Element encoding",
        "Name": "bls_pairing_e(G1,G2_invalid_field_element)=e(-G1,G2)",
        },
        {
        "Input": ""
            # G1 point (not on curve)
            + int_to_hex(int(P1[0]), 64)  # Using P1 instead of G1
            + int_to_hex(int(G1[1]), 64)
            # G2 point (point at infinity)
            + int_to_hex(0, 256),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_pairing_e(G1_not_on_curve,0)",
        },
        {
        "Input": ""
            # G1 point (point at infinity)
            + int_to_hex(0, 128)
            # G2 point (not on curve)
            + int_to_hex(int(P2[0].coeffs[0]), 64)  # Using P2 instead of G2
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_pairing_e(0,G2_not_on_curve)",
        },
        {
        "Input": ""
            # G1 point (not on curve)
            + int_to_hex(int(P1[0]), 64)  # Using P1 instead of G1
            + int_to_hex(int(G1[1]), 64)
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_pairing_e(G1_not_on_curve,G2)",
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point (not on curve)
            + int_to_hex(int(P2[0].coeffs[0]), 64)  # Using P2 instead of G2
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_pairing_e(G1,G2_not_on_curve)",
        },
        {
        "Input": ""
            # G1 point (not on curve)
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(P1[1]), 64)
            # G2 point 1
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G1 point 2
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_pairing_e(G1_not_on_curve,-G2)=e(-G1,G2)"
        },
        {
        "Input": ""
            # G1 point 1
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1 (not on curve)
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(P2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G1 point 2
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_pairing_e(G1,G2_not_on_curve)=e(-G1,G2)"
        },
        {
        "Input": ""
            # G1 point (not on curve)
            + int_to_hex(int(G1_not_in_correct_subgroup[0]), 64)
            + int_to_hex(int(G1_not_in_correct_subgroup[1]), 64)
            # G2 point (point at infinity)
            + int_to_hex(0, 256),
        "ExpectedError": "g1 point is not in the correct subgroup",
        "Name": "bls_pairing_e(G1_not_in_correct_subgroup,0)",
        },
        {
        "Input": ""
            # G1 point (point at infinity)
            + int_to_hex(0, 128)
            # G2 point (not on curve)
            + int_to_hex(int(G2_not_in_correct_subgroup[0].coeffs[0]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[0].coeffs[1]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[1].coeffs[0]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[1].coeffs[1]), 64),
        "ExpectedError": "g2 point is not in the correct subgroup",
        "Name": "bls_pairing_e(0,G2_not_in_correct_subgroup)",
        },
        {
        "Input": ""
            # G1 point (not on curve)
            + int_to_hex(int(G1_not_in_correct_subgroup[0]), 64)
            + int_to_hex(int(G1_not_in_correct_subgroup[1]), 64)
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "ExpectedError": "g1 point is not in the correct subgroup",
        "Name": "bls_pairing_e(G1_not_in_correct_subgroup,G2)",
        },
        {
        "Input": ""
            # G1 point
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point (not on curve)
            + int_to_hex(int(G2_not_in_correct_subgroup[0].coeffs[0]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[0].coeffs[1]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[1].coeffs[0]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[1].coeffs[1]), 64),
        "ExpectedError": "g2 point is not in the correct subgroup",
        "Name": "bls_pairing_e(G1,G2_not_in_correct_subgroup)",
        },
        {
        "Input": ""
            # G1 point 1 (not in the correct subgroup)
            + int_to_hex(int(G1_not_in_correct_subgroup[0]), 64)
            + int_to_hex(int(G1_not_in_correct_subgroup[1]), 64)
            # G2 point 1
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64)
            # G1 point 2
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "ExpectedError": "g1 point is not in the correct subgroup",
        "Name": "bls_pairing_e(G1_not_in_correct_subgroup,-G2)=e(-G1,G2)"
        },
        {
        "Input": ""
            # G1 point 1
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 1 (not in the correct subgroup)
            + int_to_hex(int(G2_not_in_correct_subgroup[0].coeffs[0]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[0].coeffs[1]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[1].coeffs[0]), 64)
            + int_to_hex(int(G2_not_in_correct_subgroup[1].coeffs[1]), 64)
            # G1 point 2
            + int_to_hex(int(G1[0]), 64)
            + int_to_hex(int(G1[1]), 64)
            # G2 point 2
            + int_to_hex(int(neg(G2)[0].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[0].coeffs[1]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[0]), 64)
            + int_to_hex(int(neg(G2)[1].coeffs[1]), 64),
        "ExpectedError": "g2 point is not in the correct subgroup",
        "Name": "bls_pairing_e(G1,G2_not_in_correct_subgroup)=e(-G1,G2)"
        },
        {
        "Input": ""
            # G1 point (not in correct subgroup but invalid curve)
            + int_to_hex(int(G1_in_correct_subgroup_invalid_curve[0]), 64)
            + int_to_hex(int(G1_in_correct_subgroup_invalid_curve[1]), 64)
            # G2 point
            + int_to_hex(int(G2[0].coeffs[0]), 64)
            + int_to_hex(int(G2[0].coeffs[1]), 64)
            + int_to_hex(int(G2[1].coeffs[0]), 64)
            + int_to_hex(int(G2[1].coeffs[1]), 64),
        "ExpectedError": "invalid point: not on curve",
        "Name": "bls_pairing_e(G1_in_correct_subgroup_invalid_curve,G2)",
        }
    ]


test_kinds: Dict[str, Generator[Tuple[str, Any], None, None]] = {
    'add_G1': case01_add_G1,
    'add_G2': case02_add_G2,
    'mul_G1': case03_mul_G1,
    'mul_G2': case04_mul_G2,
    'map_fp_to_G1': case05_map_fp_to_G1,
    'map_fp2_to_G2': case06_map_fp2_to_G2,
    'msm_G1': case07_msm_G1,
    'msm_G2': case08_msm_G2,
    'pairing_check': case09_pairing_check,
    'fail_add_G1': case10_fail_add_G1,
    'fail_add_G2': case11_fail_add_G2,
    'fail_mul_G1': case12_fail_mul_G1,
    'fail_mul_G2': case13_fail_mul_G2,
    'fail_map_fp_to_G1': case14_fail_map_fp_to_G1,
    'fail_map_fp2_to_G2': case15_fail_map_fp2_to_G2,
    'fail_msm_G1': case16_fail_msm_G1,
    'fail_msm_G2': case17_fail_msm_G2,
    'fail_pairing_check': case18_fail_pairing_check
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
