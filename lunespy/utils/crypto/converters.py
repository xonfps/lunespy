def from_hex(string: str) -> bytes:
    return bytes.fromhex(string)


def to_string_from_b58(data: bytes) -> str:
    from base58 import b58encode

    return b58encode(data).decode()


def to_bytes_from_b58(data: str) -> bytes:
    from base58 import b58decode

    return b58decode(data)


def validate_sign(public_key, message, signature) -> bool:
    from axolotl_curve25519 import verifySignature

    verified = verifySignature(
        to_bytes_from_b58(public_key),
        to_bytes_from_b58(message),
        to_bytes_from_b58(signature)
    )

    return True if verified == 0 else False


def hash_data(data: bytes) -> str:
    from lunespy.utils.crypto.algorithms import KeccakHash
    from hashlib import blake2b
    keccak256 = KeccakHash()

    return keccak256.digest( 
        blake2b(data, digest_size=32).digest()
    )


def sign(private_key: str, message: bytes) -> bytes:
    from axolotl_curve25519 import calculateSignature as curve
    from os import urandom

    return curve(
            urandom(64),
            to_bytes_from_b58(private_key),
            message
        )


def sha256(string: bytes) -> bytes:
    from hashlib import sha256

    return sha256(
        string
    ).digest()

