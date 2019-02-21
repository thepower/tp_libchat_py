import base64
import hashlib
import logging

from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.util import sigencode_der, sigdecode_der
from ecdsa.numbertheory import square_root_mod_prime
from ecdsa.ellipticcurve import Point


logger = logging.getLogger('powerio.keys')


# from steem-python
def _derive_y_from_x(x, is_even):
    """ Derive y point from x point """
    curve = SECP256k1.curve
    # The curve equation over F_p is:
    #   y^2 = x^3 + ax + b
    a, b, p = curve.a(), curve.b(), curve.p()
    alpha = (pow(x, 3, p) + a * x + b) % p
    beta = square_root_mod_prime(alpha, p)
    if (beta % 2) == is_even:
        beta = p - beta
    return beta


class Key(object):
    """ Базовый класс, описывающий отображение ключей. """

    _key: (SigningKey, VerifyingKey)

    @property
    def pem(self) -> str:
        """ Возврат ключа в PEM формате (строчный). """
        return self._key.to_pem().decode('ascii')

    @property
    def der(self) -> bytes:
        """ Возврат ключа в DER формате (бинарный). """
        return self._key.to_der()

    @property
    def hex(self) -> str:
        """ Возврат ключа в шестнадцатиричном преставлении."""
        return self._key.to_string().hex()

    @property
    def to_str(self) -> str:
        """ Возврат ключа в строковом преставлении."""
        return self._key.to_string()

    @staticmethod
    def from_der(der: bytes):
        raise NotImplementedError()

    @staticmethod
    def from_pem(pem: str):
        raise NotImplementedError()

    def __eq__(self, other):
        return self._key.to_der() == other.der

    def __str__(self):
        return self.pem


class PublicKey(Key):
    """ Публичный ключ. """
    def __init__(self, public_key: VerifyingKey):
        self._key = public_key

    @staticmethod
    def from_der(der: bytes) -> 'PublicKey':
        """ Импорт ключа из DER формата. """
        return PublicKey(VerifyingKey.from_der(der))

    @staticmethod
    def from_pem(pem: str) -> 'PublicKey':
        """ Импорт ключа из PEM формата. """
        return PublicKey(VerifyingKey.from_pem(pem))

    @staticmethod
    def from_bin(binary_key: bytes) -> 'PublicKey':
        """ Импорт ключа из  формата. """
        if len(binary_key) == 33:
            is_even = (binary_key[0] % 2 == 0)
            x = int(binary_key[1:].hex(), 16)
            y = _derive_y_from_x(x, is_even)
            logger.debug(f"restored y point: {y}")
            vk = VerifyingKey.from_public_point(
                point=Point(SECP256k1.curve, x, y, SECP256k1.order),
                curve=SECP256k1
            )
            return PublicKey(vk)
        elif binary_key[0] == '\x04' and len(binary_key) == 65:
            return PublicKey(VerifyingKey.from_string(binary_key[1:]))
        elif len(binary_key) == 64:
            return PublicKey(VerifyingKey.from_string(binary_key))

    @property
    def compressed(self) -> bytes:
        """ Возврат ключа в 'сжатом' формате. """
        if self._key.to_string()[63] % 2 == 0:
            return b'\x02' + self._key.to_string()[:32]
        else:
            return b'\x03' + self._key.to_string()[:32]

    @property
    def full(self):
        """ Возврат ключа в 'полном' формате. """
        return b'\x04' + self._key.to_string()

    @property
    def base64(self):
        """ Возврат ключа в 'сжатом' формате в Base64. """
        return base64.b64encode(self.compressed).decode('ascii')

    def verify_digest(self, sign: bytes, digest: bytes):
        """ Проверка подписи хеша. """
        return self._key.verify_digest(sign, digest, sigdecode=sigdecode_der)

    def __repr__(self):
        return f"PublicKey({self.compressed.hex()})"


class PrivateKey(Key):
    """ Приватный ключ. """

    def __init__(self, sk: SigningKey = None):
        if not sk:
            self._key = SigningKey.generate(curve=SECP256k1)
        else:
            self._key = sk

    def public(self) -> 'PublicKey':
        """ Получение соответствующего публичного ключа. """
        return PublicKey(self._key.get_verifying_key())

    @staticmethod
    def from_der(der: bytes) -> 'PrivateKey':
        """ Импорт приватного ключа из DER формата. """
        return PrivateKey(SigningKey.from_der(der))

    @staticmethod
    def from_string(string: str) -> 'PrivateKey':
        """ Импорт приватного ключа из string формата. """
        return PrivateKey(SigningKey.from_string(string))


    @staticmethod
    def from_pem(pem: str) -> 'PrivateKey':
        """ Импорт приватного ключа из PEM формата. """
        return PrivateKey(SigningKey.from_pem(pem))

    def sign_digest(self, digest: bytes) -> bytes:
        """ Подпись хеша. """
        return self._key.sign_digest(digest, sigencode=sigencode_der)

    def sign_message(self, msg: bytes) -> bytes:
        """ Подпись сообщения. """
        return self._key.sign(msg, hashfunc=hashlib.sha256, sigencode=sigencode_der)
