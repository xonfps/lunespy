from pytest import fixture, mark


@fixture
def accounts():
    from lunespy.client.wallet import Account
    pk1 = "8YMbX5BCQdazwgdVfeUpKuoUJrmYpMyGVAGAsNaHVj1u"
    pk2 = "G6E2xNBWtsRG8XBDmeTQQxZNHHUa6K9dnc9KrYtKyGwM"

    return {
        "from": Account(private_key=pk1),
        "to": Account(private_key=pk2)
    }


@fixture
def basic_transfer_token(accounts):
    from lunespy.client.transactions.transfer import TransferToken
    from lunespy.utils import now

    return TransferToken(
        sender=accounts["from"].public_key,
        receiver=accounts["to"].address,
        amount=1000,
        chain="mainnet",
        timestamp=now()
    )


def test_transfer_ready(basic_transfer_token):
    """
        with a Account in chain `mainnet`:
    """

    assert basic_transfer_token.ready == True


def test_transfer_transaction(basic_transfer_token, accounts):
    """
        with a Account in chain `mainnet`:
    """
    from lunespy.client.transactions.constants import TransferType

    assert basic_transfer_token.transaction == {
        "ready": True,
        "type":  TransferType.to_int.value,
        "sender": accounts["from"].address,
        "senderPublicKey": accounts["from"].public_key,
        "recipient": accounts["to"].address,
        "amount": 100000000000,
        "timestamp": basic_transfer_token.timestamp,
        "fee": TransferType.fee.value,
        "assetId": "",
        "feeAsset": ""
    }


def test_transfer_sign(basic_transfer_token, accounts):
    from lunespy.utils.crypto.converters import validate_sign

    tx = basic_transfer_token.sign(
        accounts["from"].private_key
    )
    assert True == validate_sign(
        accounts["from"].public_key,
        tx["rawData"],
        tx["signature"]
    )
