def address_generator(public_key: bytes, chain_id: str, address_version: int) -> bytes:
    from lunespy.utils.crypto.converters import hash_data

    public_key_hash = hash_data(public_key)[:20]

    raw_address = (address_version + chain_id + public_key_hash)
    checksum = hash_data(raw_address.encode('latin-1'))[:4]

    return (raw_address + checksum).encode('latin-1')


def new_seed_generator(n_words: int) -> str:
    from lunespy.client.wallet.constants import word_list
    from os import urandom

    def f():
        wordCount = 2048
        r = urandom(4).decode('latin-1')
        x = (ord(r[3])) + (ord(r[2]) << 8) + (ord(r[1]) << 16) + (ord(r[0]) << 24)
        w1 = x % wordCount
        w2 = ((int(x / wordCount) >> 0) + w1) % wordCount
        w3 = ((int((int(x / wordCount) >> 0) / wordCount) >> 0) + w2) % wordCount
        return w1, w2, w3

    n_words_multiple_of_3: int = n_words // 3

    return " ".join([
        word_list[n]
        for _ in range(n_words_multiple_of_3)
        for n in f()
    ])


def seed_generator(seed: str, nonce: int, chain_id: str, address_version: int) -> dict:
    from lunespy.utils.crypto.converters import to_string_from_b58, hash_data, sha256, from_hex
    from axolotl_curve25519 import generatePrivateKey, generatePublicKey
    from struct import pack

    nonce_seed: str = (pack(">L", nonce) + seed.encode('latin-1')).hex()
    raw_seed: str = hash_data(from_hex(nonce_seed)).encode('latin-1').hex()
    hash_seed: str = sha256(from_hex(raw_seed)).hex()

    private_key: str = generatePrivateKey(from_hex(hash_seed)).hex()
    public_key: str = generatePublicKey(from_hex(private_key)).hex()
    address = address_generator(from_hex(public_key), chain_id, address_version).hex()

    return {
        'seed': seed,
        'nonce': nonce,
        'chain': 'mainnet' if chain_id == '1' else 'testnet',
        'private_key': to_string_from_b58(from_hex(private_key)),
        'public_key': to_string_from_b58(from_hex(public_key)),
        'address': to_string_from_b58(from_hex(address))
    }


def private_key_generator(private_key: str, chain_id: str, address_version: int) -> dict:
    from lunespy.utils.crypto.converters import to_string_from_b58, to_bytes_from_b58, from_hex
    from axolotl_curve25519 import generatePublicKey

    public_key = generatePublicKey(to_bytes_from_b58(private_key)).hex()
    address = address_generator(from_hex(public_key), chain_id, address_version).hex()

    return {
        'chain': 'mainnet' if chain_id == '1' else 'testnet',
        'chain_id': chain_id,
        'private_key': private_key,
        'public_key': to_string_from_b58(from_hex(public_key)),
        'address': to_string_from_b58(from_hex(address))
    }


def public_key_generator(public_key: str, chain_id: str, address_version: int) -> dict:
    from lunespy.utils.crypto.converters import to_string_from_b58, from_hex, to_bytes_from_b58

    return {
        'chain': 'mainnet' if chain_id == '1' else 'testnet',
        'public_key': public_key,
        'address': to_string_from_b58(address_generator(to_bytes_from_b58(public_key), chain_id, address_version))
    }


def validate_address(address: str, chain_id: str) -> bool:
    from lunespy.client.wallet.errors import InvalidChecksumAddress ,InvalidVersionAddress ,InvalidLengthAddress, InvalidChainAddress
    from lunespy.client.wallet.constants import ADDRESS_CHECKSUM_LENGTH, ADDRESS_VERSION, ADDRESS_LENGTH
    from lunespy.utils.crypto.converters import to_bytes_from_b58, hash_data

    def slice(string: str, index: int) -> tuple[str]:
        return string[:-index], string[-index:]

    raw_address: str = to_bytes_from_b58(address).decode('latin-1')
    address_left, checksum = slice(raw_address, ADDRESS_CHECKSUM_LENGTH)
    hash_address_left: str = hash_data(address_left.encode('latin-1'))
    chain: str = hash_address_left[:ADDRESS_CHECKSUM_LENGTH]

    if checksum != chain:
        raise InvalidChecksumAddress
    elif raw_address[0] not in ADDRESS_VERSION:
        raise InvalidVersionAddress
    elif raw_address[1] != chain_id:
        raise InvalidChainAddress
    elif len(raw_address) != ADDRESS_LENGTH:
        raise InvalidLengthAddress

    return True


def new(n_words, seed, nonce, chain, private_key, public_key, address, address_version):
    from lunespy.client.wallet.errors import InvalidNonce, InvalidData
    from lunespy.client.wallet.constants import ADDRESS_VERSION

    match (n_words, seed, nonce, chain, private_key, public_key, address, address_version):

        case (None, None, _, _, None, None, None, _):
            address_version = address_version if address_version else ADDRESS_VERSION[0]
            chain = chain if chain else "mainnet"
            chain_id = "1" if chain == "mainnet" else "0"
            nonce = nonce if nonce else 0
            n_words: int = 12
            seed: str = new_seed_generator(n_words)
            return seed_generator(seed=seed, nonce=0, chain_id=chain_id, address_version=address_version)

        case (n_words, None, _, _, None, None, None, _) if n_words is not None:
            address_version = address_version if address_version else ADDRESS_VERSION[0]
            chain = chain if chain else "mainnet"
            chain_id = "1" if chain == "mainnet" else "0"
            nonce = nonce if nonce else 0
            if nonce not in range(0, 4_294_967_295 + 1):
                InvalidNonce
            seed: str = new_seed_generator(n_words)
            return seed_generator(seed=seed, nonce=0, chain_id=chain_id, address_version=address_version)

        case (None, None, _, _, None, None, address, _) if address is not None:
            address_version = address_version if address_version else ADDRESS_VERSION[0]
            chain = chain if chain else "mainnet"
            chain_id = "1" if chain == "mainnet" else "0"
            validate_address(address=address, chain_id=chain_id)
            return {"address": address, "chain_id": chain_id}

        case (None, None, _, _, None, public_key, _, _) if public_key is not None:
            address_version = address_version if address_version else ADDRESS_VERSION[0]
            chain = chain if chain else "mainnet"
            chain_id = "1" if chain == "mainnet" else "0"
            return public_key_generator(public_key=public_key, chain_id=chain_id, address_version=address_version)

        case (None, None, _, _, private_key, _, _, _) if private_key is not None:
            address_version = address_version if address_version else ADDRESS_VERSION[0]
            chain = chain if chain else "mainnet"
            chain_id = "1" if chain == "mainnet" else "0"
            return private_key_generator(private_key=private_key, chain_id=chain_id, address_version=address_version)

        case (_, seed, _, _, _, _, _, _) if seed is not None:
            address_version = address_version if address_version else ADDRESS_VERSION[0]
            chain = chain if chain else "mainnet"
            nonce = nonce if nonce else 0
            chain_id = "1" if chain == "mainnet" else "0"
            if nonce not in range(0, 4_294_967_295 + 1):
                InvalidNonce
            return seed_generator(seed=seed, nonce=nonce, chain_id=chain_id, address_version=address_version)

        case _:
            InvalidData

