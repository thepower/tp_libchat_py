import unittest
import hashlib
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import sigencode_der, sigdecode_der
from powerio.keys import PrivateKey, PublicKey


class PrivateKeyTestCase(unittest.TestCase):
    """ Тестирование методов PrivateKey. """

    def setUp(self):
        self.sk = SigningKey.generate(curve=SECP256k1)
        self.vk = self.sk.get_verifying_key()
        self.priv = PrivateKey(self.sk)
        self.pub = PublicKey(self.vk)

    def test_to_pem(self):
        self.assertEqual(self.priv.pem, self.sk.to_pem().decode('ascii'))

    def test_to_der(self):
        self.assertEqual(self.priv.der, self.sk.to_der())

    def test_sign(self):
        msg = b'123'
        signature = self.priv.sign_message(msg)
        is_verified = self.vk.verify(
            signature, msg, hashfunc=hashlib.sha256, sigdecode=sigdecode_der)
        self.assertTrue(is_verified)

    def test_sign_digest(self):
        msg = b'123'
        digest = hashlib.sha256(msg).digest()
        signature = self.priv.sign_digest(digest)
        is_verified = self.vk.verify_digest(
            signature, digest=digest, sigdecode=sigdecode_der)
        self.assertTrue(is_verified)

    def test_eq(self):
        priv2 = PrivateKey.from_pem(self.priv.pem)
        self.assertEqual(self.priv, priv2)

    def test_str(self):
        self.assertTrue(str(self.priv), self.sk.to_pem().decode('ascii'))


class PublicKeyTestCase(unittest.TestCase):
    """ Тестирование методов PublicKey. """

    def setUp(self):
        self.sk = SigningKey.generate(curve=SECP256k1)
        self.vk = self.sk.get_verifying_key()
        self.priv = PrivateKey(self.sk)
        self.pub = PublicKey(self.vk)

    def test_pem(self):
        self.assertEqual(self.pub.pem, self.vk.to_pem().decode('ascii'))

    def test_der(self):
        self.assertEqual(self.pub.der, self.vk.to_der())

    def test_compressed_1(self):
        cmpr = self.pub.compressed
        # self.assertEqual(cmpr[0], 0x2)
        self.assertTrue(len(cmpr), 33)

    def test_compressed_2(self):
        cmpr = self.pub.compressed
        # self.assertEqual(cmpr[0], 0x3)
        self.assertTrue(len(cmpr), 33)

    def test_verify_digest(self):
        msg = b'123'
        signature = self.sk.sign(
            msg, hashfunc=hashlib.sha256, sigencode=sigencode_der)
        digest = hashlib.sha256(msg).digest()
        self.assertTrue(self.pub.verify_digest(signature, digest))

    def test_eq(self):
        pub2 = PublicKey.from_pem(self.pub.pem)
        self.assertEqual(self.pub, pub2)

    def test_repr(self):
        repr_ = "PublicKey({})".format(self.pub.compressed.hex())
        self.assertTrue(repr(self.pub), repr_)

    def test_str(self):
        self.assertTrue(str(self.pub), self.sk.to_pem().decode('ascii'))


if __name__ == '__main__':
    unittest.main()
