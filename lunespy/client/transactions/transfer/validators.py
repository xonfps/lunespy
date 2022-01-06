from lunespy.utils.crypto.converters import bytes_to_string


def validate_transfer(sender: str, receiver: str, amount: int, chain: str) -> bool:
    from lunespy.client.wallet.validators import validate_address
    from lunespy.utils import bcolors
    from base58 import alphabet


    if amount <= 0:
        print(bcolors.FAIL + 'Amount dont should be more than 0' + bcolors.ENDC)
        return False
    elif not all([i in alphabet.decode() for i in sender]):
        print(bcolors.FAIL + 'Sender invalid `public key`' + bcolors.ENDC)
        return False
    elif not validate_address(receiver, "1" if chain == "mainnet" else "0"):
        return False
    else:
        return True


def mount_transfer(sender: str, timestamp: str, receiver: str, asset_fee: str, asset_id: str, amount: int, chain_id: str, fee: int) -> dict:
    from lunespy.client.transactions.constants import TransferType
    from lunespy.utils.crypto.converters import to_machine_b58
    from lunespy.client.wallet.generators import address_generator

    address = address_generator(to_machine_b58(sender), chain_id)['address']
    return {
        "type": TransferType.to_int.value,
        "senderPublicKey": sender,
        "timestamp": timestamp,
        "recipient": receiver,
        "feeAsset": asset_fee,
        "assetId": asset_id,
        "amount": amount,
        "sender": address,
        "fee": fee
    }


def sign_transaction(private_key: str, **tx: dict) -> dict:
    from lunespy.utils.crypto.converters import to_machine_b58, to_human_b58
    from lunespy.client.transactions.constants import TransferType
    from lunespy.utils.crypto.converters import sign
    from struct import pack


    bytes_data: bytes = TransferType.to_byte.value + \
        to_machine_b58(tx["senderPublicKey"]) + \
        (b'\1' + to_machine_b58(tx["assetId"]) if tx["assetId"] != "" else b'\0') + \
        (b'\1' + to_machine_b58(tx["feeAsset"]) if tx["feeAsset"] != "" else b'\0') + \
        pack(">Q", tx["timestamp"]) + \
        pack(">Q", tx["amount"]) + \
        pack(">Q", tx["fee"]) + \
        to_machine_b58(tx["recipient"])

    tx["signature"] = to_human_b58(sign(private_key, bytes_data))
    tx["rawData"] = to_human_b58(bytes_data)
    return tx


# todo async
def send_transfer(mount_tx: dict, node_url: str) -> dict:
    from requests import post

    response = post(
        f'{node_url}/transactions/broadcast',
        json=mount_tx,
        headers={
            'content-type':
            'application/json'
        })

    if response.status_code in range(200, 300):
        mount_tx.update({
            'send': True,
            'response': response.json()
        })
        return mount_tx
    else:
        mount_tx.update({
            'send': False,
            'response': response.text
        })
        return mount_tx
