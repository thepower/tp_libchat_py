import re
from zlib import crc32
from powerio.errors import InvalidPrivateAddressError, \
    InvalidPublicAddressError, InvalidCheckSumError, AddressOutOfBoundError

# регекс на приватный адрес.
private_addr_regex = re.compile(r'^[A-F0-9]{18}$')
# регекс на публичный адрес.
public_addr_regex = re.compile(r'^[A-Z]{2}\d{18}$')

# b'100' << 61
_PUB_ADDR_BASE = 4 << 61


class Address(object):
    """ Базовый класс для адресов. """

    def __init__(self, addr: str):
        self._hex_addr = ''
        self._addr = addr

    @property
    def bin(self) -> bytes:
        return bytes.fromhex(self._hex_addr)

    @property
    def hex(self) -> str:
        return self._hex_addr

    def __str__(self) -> str:
        return self._addr

    def __eq__(self, other):
        return self._addr == str(other)


class PublicAddress(Address):
    """ Публичный адрес. """

    def __init__(self, addr: str):
        super().__init__(addr)
        self._addr = addr.upper()
        if not public_addr_regex.match(self._addr):
            raise InvalidPublicAddressError()
        self._hex_addr = PublicAddress.txt2bin(self._addr)

    @staticmethod
    def from_bin(binary: (str, bytes)) -> 'PublicAddress':
        if isinstance(binary, bytes):
            binary = binary.hex()
        return PublicAddress(PublicAddress.bin2txt(binary))

    @staticmethod
    def txt2bin(addr: str) -> str:
        """ Перевод публичного адреса из текстового представления в бинарный
        (шестнадцатиричное представление).

        Args:
            addr: публичный адрес в текстовом представлении.

        Returns:
            str: публичный адрес в бинарном представлении (шестнадцатиричное
            представление).

        """
        b_addr = bytes(addr.upper(), 'utf-8')
        # Расчет идентификатора группы.
        # 65 - смещение 'A' символа в ASCII, 48 - смещение символа '0'.
        group_id = (b_addr[0] - 65) * 2600 + (b_addr[1] - 65) * 100 + \
                   (b_addr[2] - 48) * 10 + (b_addr[3] - 48)

        # Расчет общего идентификатора.
        address_id = int(addr[4:-2])

        # Выход адреса за рамки допустимых значений.
        # int('1' * 16, 2) и int('1'* 45, 2)
        if group_id > 65535 or address_id > 35184372088831:
            raise AddressOutOfBoundError()

        # Расчет итогового адреса.
        hex_bin_addr = hex(_PUB_ADDR_BASE + (group_id << 45) + address_id)[2:]
        # Расчет контрольной суммы.
        checksum = crc32(bytes.fromhex(hex_bin_addr))
        # Проверка контрольной суммы.
        if checksum % 100 != int(addr[-2:]):
            raise InvalidCheckSumError()
        return hex_bin_addr.upper()

    @staticmethod
    def bin2txt(bin_addr: (str, bytes)) -> str:
        """

        Args:
            bin_addr: публичный адрес в бинарном представлении (байтовом либо
            шестнадцатиричной строкой).

        Returns:
            str: публичный адрес в текстовом представлении.

        """
        if isinstance(bin_addr, bytes):
            bin_addr = bin_addr.hex()

        format_string = "{:c}{:c}{:d}{:d}{:014d}{:02d}"
        int_addr = int(bin_addr, 16)
        b_addr = bin(int_addr)[2:]

        # Разбиение адреса на логические участки (идентификаторы группы, общий).
        group_part = int(b_addr[3:19], 2)
        decimal_part = int(b_addr[19:], 2)

        # Преобразование.
        first_letter = group_part // 2600 + 65
        group_part = group_part % 2600
        second_letter = group_part // 100 + 65
        group_part = group_part % 100
        third_num = group_part // 10

        # Расчет контрольной суммы.
        checksum = crc32(bytes.fromhex(bin_addr)) % 100

        res = format_string.format(first_letter, second_letter, third_num,
                                   group_part % 10, decimal_part, checksum)
        return res

    def __repr__(self):
        return f"PublicAddress(addr='{self._addr}', hex='{self._hex_addr}')"


class PrivateAddress(Address):
    """ Приватный адрес. """

    def __init__(self, addr: str):
        """

        Args:
            addr: текстовое представление адреса.

        """
        super().__init__(addr)
        self._addr = addr.upper()
        if not private_addr_regex.match(self._addr):
            raise InvalidPrivateAddressError()
        self._hex_addr = PrivateAddress.txt2bin(addr)

    @staticmethod
    def from_bin(bin_addr: (str, bytes)) -> 'PrivateAddress':
        if isinstance(bin_addr, bytes):
            bin_addr = bin_addr.hex()
        txt_addr = PrivateAddress.bin2txt(bin_addr)
        return PrivateAddress(txt_addr)

    @staticmethod
    def txt2bin(addr: str) -> str:
        """ Перевод приватного адреса из текстового представления в бинарный
        (шестнадцатиричное представление).

        Args:
            addr (str): приватный адрес в текстовом представлении.

        Returns:
            str: приватный адрес в бинарном представлении (шестнадцатиричное
            представление).

        """
        hex_bin_addr = hex(int(addr[:1], 16) & 11 | 10)[2:] + addr[1:]
        checksum = hex(crc32(bytes.fromhex(hex_bin_addr[:-2])))[-2:]
        if checksum.upper() != addr[-2:].upper():
            raise InvalidCheckSumError()
        return hex_bin_addr[:-2].upper()

    @staticmethod
    def bin2txt(bin_addr: (str, bytes)) -> str:
        """ Перевод приватного адреса из бинарного представления в текстовое.

        Args:
            bin_addr: бинарный приватный адрес в шестнадцатиричном
            представлении либо бинарном виде.

        Returns:
            str: приватный адрес в текстовом представлении.

        """
        if isinstance(bin_addr, bytes):
            bin_addr = bin_addr.hex()
        checksum = hex(crc32(bytes.fromhex(bin_addr)))[-2:]
        addr = hex(int(bin_addr[:1], 16) & 1)[2:] + bin_addr[1:] + checksum
        return addr.upper()

    def __repr__(self):
        return f"PrivateAddress(addr='{self._addr}', hex='{self._hex_addr}')"
