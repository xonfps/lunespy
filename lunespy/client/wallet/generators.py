from lunespy.utils.crypto.converters import to_human_b58, to_machine_b58
from lunespy.utils.crypto.converters import string_to_bytes
from lunespy.utils.crypto.converters import hash_data
from lunespy.client.wallet.constants import word_list
from os import urandom


def address_generator(public_key: bytes, chain_id: str) -> dict:
    un_hashed_address = chr(1) + str(chain_id) + hash_data(public_key)[0:20]
    address_hash = hash_data(string_to_bytes(un_hashed_address))[0:4]
    address = to_human_b58(string_to_bytes(un_hashed_address + address_hash))
    public_key_b58 = to_human_b58(public_key)
    return {
        'seed': "",
        'hash_seed': "",
        'nonce': 0,
        'chain': 'mainnet' if chain_id == '1' else 'testnet',
        'chain_id': chain_id,
        'private_key': "",
        'public_key': public_key_b58,
        'address': address
    }


def new_seed_generator(n_words: int) -> str:
    from lunespy.utils.crypto.converters import bytes_to_string

    def f():
        wordCount = 2048
        r = bytes_to_string(urandom(4))
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


def seed_generator(seed: str, nonce: int, chain_id: str) -> dict:
    from lunespy.utils.crypto.converters import sha256
    from axolotl_curve25519 import generatePrivateKey, generatePublicKey
    from struct import pack

    hash_seed = hash_data(
        pack(">L", nonce) + string_to_bytes(seed)
    )
    account_hash_seed = sha256(hash_seed)
    private_key = generatePrivateKey(account_hash_seed)
    public_key = generatePublicKey(private_key)
    address = address_generator(public_key, chain_id)
    return {
        'seed': seed,
        'hash_seed': to_human_b58(seed),
        'nonce': nonce,
        'chain': 'mainnet' if chain_id == '1' else 'testnet',
        'chain_id': chain_id,
        'private_key': to_human_b58(private_key),
        'public_key': to_human_b58(public_key),
        'address': address['address']
    }


def private_key_generator(private_key: str, chain_id: str) -> dict:
    from axolotl_curve25519 import generatePublicKey

    private_key_b58 = to_machine_b58(private_key)
    public_key = generatePublicKey(private_key_b58)
    address = address_generator(public_key, chain_id)
    return {
        'seed': "",
        'hash_seed': "",
        'nonce': 0,
        'chain': 'mainnet' if chain_id == '1' else 'testnet',
        'chain_id': chain_id,
        'private_key': to_human_b58(private_key_b58),
        'public_key': to_human_b58(public_key),
        'address': address['address']
    }


def public_key_generator(public_key: str, chain_id: str) -> dict:
    public_key_b58 = to_machine_b58(public_key)
    address = address_generator(public_key_b58, chain_id)
    return {
        'seed': "",
        'hash_seed': "",
        'nonce': 0,
        'chain': 'mainnet' if chain_id == '1' else 'testnet',
        'chain_id': chain_id,
        'private_key': "",
        'public_key': to_human_b58(public_key_b58),
        'address': address['address']
    }


def wallet_generator(**data: dict) -> dict:
    if data.get('seed', False):
        return seed_generator(seed=data['seed'], nonce=data['nonce'], chain_id=data['chain_id'])

    elif data.get('private_key', False):
        return private_key_generator(private_key=data['private_key'], chain_id=data['chain_id'])

    elif data.get('public_key', False):
        return public_key_generator(public_key=data['public_key'], chain_id=data['chain_id'])

    elif data.get('address', False):
        return address_generator(public_key="", chain_id=data['chain_id'])

    elif data.get('n_words', False):
        seed = new_seed_generator(n_words=data['n_words'])
        return seed_generator(seed=seed, nonce=data['nonce'], chain_id=data['chain_id'])

    else:
        n_words: int = 12
        seed: str = new_seed_generator(n_words)
        return seed_generator(seed=seed, nonce=data['nonce'], chain_id=data['chain_id'])
