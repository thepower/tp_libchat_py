import unittest
from powerio import PrivateAddress, PublicAddress
from powerio.errors import AddressOutOfBoundError


TEST_PUB_ADDRS = [
    {'addr': 'AA100000005033211991', 'hex': '80014000030001D7'},
    {'addr': 'AA100000001677722412', 'hex': '8001400001000008'},
    {'addr': 'AA100000001677923612', 'hex': '80014000010007E4'}
]


TEST_PRIV_ADDRS = [
    {'addr': '00000000FE00007DF0', 'hex': 'A0000000FE00007D'},
    {'addr': '000000000A0000050E', 'hex': 'A00000000A000005'}
]


class PrivateAddressTestCase(unittest.TestCase):
    """ Тестирование методов класса PrivateAddress. """

    def test_txt2bin(self):
        for addr in TEST_PRIV_ADDRS:
            with self.subTest(addr=addr):
                hex_addr = PrivateAddress.txt2bin(addr['addr'])
                self.assertEqual(hex_addr, addr['hex'])

    def test_bin2txt(self):
        for addr in TEST_PRIV_ADDRS:
            with self.subTest(addr=addr):
                txt_addr = PrivateAddress.bin2txt(addr['hex'])
                self.assertEqual(txt_addr, addr['addr'])

    def test_from_bin(self):
        for addr in TEST_PRIV_ADDRS:
            with self.subTest(addr=addr):
                priv1 = PrivateAddress.from_bin(addr['hex'])
                priv2 = PrivateAddress(addr['addr'])
                self.assertEqual(priv1, priv2)

    def test_hex_property(self):
        for addr in TEST_PRIV_ADDRS:
            with self.subTest(addr=addr):
                priv = PrivateAddress(addr['addr'])
                self.assertEqual(priv.hex, addr['hex'])

    def test_bin_property(self):
        for addr in TEST_PRIV_ADDRS:
            with self.subTest(addr=addr):
                priv = PrivateAddress(addr['addr'])
                self.assertEqual(priv.bin, bytes.fromhex(addr['hex']))

    def test_repr(self):
        self.assertEqual(
            repr(PrivateAddress('00000000FE00007DF0')),
            "PrivateAddress(addr='00000000FE00007DF0', hex='A0000000FE00007D')"
        )

    def test_str(self):
        self.assertEqual(
            str(PrivateAddress('00000000FE00007DF0')),
            "00000000FE00007DF0"
        )

    def test_eq(self):
        self.assertEqual(
            PrivateAddress('00000000FE00007DF0'),
            PrivateAddress('00000000FE00007DF0')
        )


class PublicAddressTestCase(unittest.TestCase):
    """ Тестирование методов класса PublicAddress. """

    def test_txt2bin(self):
        for addr in TEST_PUB_ADDRS:
            with self.subTest(addr=addr):
                hex_addr = PublicAddress.txt2bin(addr['addr'])
                self.assertEqual(hex_addr, addr['hex'])

    def test_bin2txt(self):
        for addr in TEST_PUB_ADDRS:
            with self.subTest(addr=addr):
                txt_addr = PublicAddress.bin2txt(addr['hex'])
                self.assertEqual(txt_addr, addr['addr'])

    def test_from_bin(self):
        for addr in TEST_PUB_ADDRS:
            with self.subTest(addr=addr):
                pub1 = PublicAddress.from_bin(addr['hex'])
                pub2 = PublicAddress(addr['addr'])
                self.assertEqual(pub1, pub2)

    def test_hex_property(self):
        for addr in TEST_PUB_ADDRS:
            with self.subTest(addr=addr):
                pub = PublicAddress(addr['addr'])
                self.assertEqual(pub.hex, addr['hex'])

    def test_bin_property(self):
        for addr in TEST_PUB_ADDRS:
            with self.subTest(addr=addr):
                pub = PublicAddress(addr['addr'])
                self.assertEqual(pub.bin, bytes.fromhex(addr['hex']))

    def test_out_of_bound_error(self):
        with self.assertRaises(AddressOutOfBoundError):
            PublicAddress.txt2bin('ZZ999999999999999999')

    def test_repr(self):
        msg = "PublicAddress(addr='{addr}', hex='{hex}')"
        for pub_addr in TEST_PUB_ADDRS:
            with self.subTest(addr=pub_addr):
                a = PublicAddress(pub_addr['addr'])
                self.assertEqual(repr(a), msg.format(**pub_addr))

    def test_str(self):
        for pub_addr in TEST_PUB_ADDRS:
            with self.subTest(addr=pub_addr):
                a = PublicAddress(pub_addr['addr'])
                self.assertEqual(str(a), pub_addr['addr'])

    def test_eq(self):
        self.assertEqual(
            PublicAddress('AA100000005033211991'),
            PublicAddress('AA100000005033211991')
        )


if __name__ == '__main__':
    unittest.main()
