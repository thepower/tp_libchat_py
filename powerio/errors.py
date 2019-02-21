
ERRORS_ENUM = {
    10000: "Address not found in current chain.", # /where
    10001: "Invalid address. Checksum error in text representation.", # /where
    10002: "Invalid address. Error while attempt to establish address chain.", # /where
    10003: "Address not found in current chain.", # /address
    10004: "Invalid address. Checksum error in text representation.", # /address
    10005: "Invalid address. Error while attempt to establish address chain.",
    10006: "Block with provided hash not found", # /address
    10007: "Unknown exception during address registration", # /register
    10008: "Error on new transaction from user", # /tx/new
    10009: "Contract address not found", # /contract
    10010: "Invalid contract address. Checksum error in text representation.", # /contract,
    10011: "Contract address not found", # /contract/{addr}/call
    10012: "Invalid contract address. Checksum error in text representation." # /contract/{addr}/call
}

"""
    ApiException описывает ошибки, приходящие с удаленной ноды.
"""


class ApiException(Exception):
    pass


class AddressNotFoundError(ApiException):
    pass


class BlockNotFoundError(ApiException):
    pass


"""
    Ошибки, возникающие при работе с адресами:
        - неверные чексуммы.
        - неверный формат адреса (некорректные символы, длина).
        - адрес находится вне допустимого диапазона.
"""


class AddressError(Exception):
    pass


class InvalidPrivateAddressError(AddressError):
    pass


class InvalidPublicAddressError(AddressError):
    pass


class AddressOutOfBoundError(AddressError):
    pass


class InvalidCheckSumError(AddressError):
    pass

