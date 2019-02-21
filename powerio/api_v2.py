import hashlib
import binascii
import time
import msgpack
import requests
import struct
import base64

from powerio.address import PublicAddress
from powerio.keys import PrivateKey, PublicKey
from powerio.errors import ApiException

class ClientII:

    @staticmethod
    def get_endpoint_settings():
        return {
            'url': 'http://wallet.thepower.io/api/chain/3/',
            'new_tx': 'tx/new',
            'tx_status': 'tx/status',
            'address_info': 'address',
            'block_info': 'block',
        }


    def hash_array_keys(self, keys):
        # if isinstance(keys, list):
        # keys.sort()
        # hk = binascii.unhexlify(''.join(keys))
        hash = hashlib.sha256(keys).hexdigest().upper()
        # elif not isinstance(keys, list):
        #     raise TypeError("keys is not array")

        return hash

    def get_timestamp(self):
        micro_sec = int(round(time.time() * 1000))

        return micro_sec

    def get_time_nonce(self):
        sec = int(round(time.time() * 1000))
        micro_sec = int(round(time.time() * 10000000))

        return int(str(sec) + str(micro_sec)[11:])

    def encode_map(self, data):
        pack = msgpack.packb(data, use_bin_type=True)
        return pack

    # check difficulty
    def is_difficulty_not_enough(self, data, difficulty):
        if difficulty == 0:
            return False
        diff = 0
        data_hash = hashlib.sha512(data).hexdigest()
        bin_rez = ''.join(["{0:04b}".format(int(c, 16)) for c in data_hash.decode('ascii')])
        # bin_rez = ''.join(["{0:04b}".format(int(c,16)) for c in "3890c8e314282271d4050d049adf70722210e4147551b76edfc74e2fb9977bbf5ef41f4cc83d38144adc6bc52c93d3d1fb30473b043bf2f3b91c05dfcb6835a0"])
        for x in bin_rez:
            if x == "0":
                diff += 1
            if x == "1":
                break

        if difficulty == diff:
            return False
        else:
            return True

    # SIGN
    # TLV body
    def tlv_add_timestamp(self, timestamp):
        tag = 0x01
        length = 0x08
        time = timestamp
        res = struct.pack('!BBQ', tag, length, time)
        return res

    def tlv_add_pubkey(self, pubkey):
        tag = 0x02
        length = len(pubkey)
        if length > 0xFF:
            raise TypeError("pubkey to long")
        if length < 1:
            raise TypeError("pubkey is wrong")
        res = struct.pack('BB', tag, length)
        return res + pubkey

    def tlv_add_sign(self, pk, pubkey, timestamp, body):
        tag = 0xFF
        data = self.tlv_add_timestamp(timestamp) + self.tlv_add_pubkey(pubkey) + body
        result = pk.sign_message(data)
        length = len(result)
        res = struct.pack('BB', tag, length)
        return res + result

    def generate_sign_data(self, private_key, public_key, time, body_bin):
        data = self.tlv_add_sign(private_key, public_key, time, body_bin) + self.tlv_add_timestamp(time) + self.tlv_add_pubkey(public_key)
        return data

    # Body pack message
    def registration_tx_body(self, publickey, difficulty, time):
        # if isinstance(publickey, list):
        current_nonce = 0

        data = {
            'k': 0x11,
            't': time,
            'nonce': current_nonce,
            'h': binascii.unhexlify(self.hash_array_keys(publickey))
        }

        body_bin = self.encode_map(data)

        while self.is_difficulty_not_enough(body_bin, difficulty):
            current_nonce += 1
            data['nonce'] = current_nonce
            body_bin = self.encode_map(data)

        return body_bin

    # elif not isinstance(publickey, list):
    #     raise TypeError("keys is not array")

    def transfer_tx_body(self, fr, to, money, time, nonce, msg):
        data = {
            'k': 0x10,
            'f': fr,
            'to': to,
            's': nonce,
            't': time,
            'p': money,
            'e': msg
        }

        body_bin = self.encode_map(data)

        return body_bin

    def pack_tx(self, msg, signature):
        data = {
            'body': msg,
            'sig': [signature],
            'ver': 2
        }
        return msgpack.packb(data, use_bin_type=True)
    
    def form_pay_object(self, amount, type = 'SK'):
        return [[0x00, type, amount], [0x01, 'SK', 1]]
    	
    # Examples functions
    def registration(self, private_key, times, difficulty = 0):
        settings = ClientII.get_endpoint_settings()
        public_key = private_key.public().compressed
        tx = base64.b64encode(self.pack_tx(self.registration_tx_body(public_key, difficulty, times), self.generate_sign_data(private_key, public_key, times, self.registration_tx_body(public_key, difficulty, times))))
        data = {"tx": str(tx)[2:-1]}
        url = settings['url'] + settings['new_tx']
        resp = requests.post(url, json=data).json()
        if resp['ok'] is False:
            raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
        else:
            time.sleep(10)
            status_url = settings['url'] + settings['tx_status']
            status_resp = requests.get(status_url + '/' + resp['txid']).json()
            if status_resp['ok'] is False:
                raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
            else:
                i = 0
                while (status_resp['res'] is None) and (i < 10):
                    i += 1
                    print('Try get registered address. #' + str(i) + "   " + status_url + '/' + resp['txid'])
                    time.sleep(2)
                    status_resp = requests.get(status_url + '/' + resp['txid']).json()
                if status_resp['ok'] is False:
                    raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
                else:
                    if status_resp['res'] is None:
                        return print("Can't get address after 10 attempt")
                    else:
                        return status_resp


    def get_last_block_info(self, block, addr):
        settings = ClientII.get_endpoint_settings()
        url = settings['url'] + settings['block_info']
        time.sleep(2)
        resp = requests.get(url + '/' + block, params={'addr': addr}).json()
        result = {}
        if resp['ok'] is False:
            raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
        else:
            i = 0
            while i < len(list(resp['block']['txs'].keys())):
                if resp['block']['txs'][list(resp['block']['txs'].keys())[i]]['from'] == PublicAddress.txt2bin(addr):

                    result[str(i)] = {'block': block}
                    result[str(i)]['addr'] = addr
                    result[str(i)]['to'] = PublicAddress.bin2txt(resp['block']['txs'][list(resp['block']['txs'].keys())[i]]['to'])
                    result[str(i)]['tr_am'] = resp['block']['txs'][list(resp['block']['txs'].keys())[i]]['payload'][0]['amount']
                    result[str(i)]['tr_cur'] = resp['block']['txs'][list(resp['block']['txs'].keys())[i]]['payload'][0]['cur']
                    if 'txext' in resp['block']['txs'][list(resp['block']['txs'].keys())[i]]:
                        result[str(i)]['msg'] = resp['block']['txs'][list(resp['block']['txs'].keys())[i]]['txext']['msg']
                i += 1
        return result

    def get_block_info(self, block):
        settings = ClientII.get_endpoint_settings()
        url = settings['url'] + settings['block_info']
        time.sleep(2)
        resp = requests.get(url + '/' + block).json()
        result = {}
        if resp['ok'] is False:
            raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
        else:

            result = resp['block']
        return result

    def get_prev_block_info(self, block, addr):
        settings = ClientII.get_endpoint_settings()
        url = settings['url'] + settings['block_info']
        time.sleep(2)
        result = {}
        resp = requests.get(url + '/' + block, params={'addr': addr}).json()
        # print(resp)
        if resp['ok'] is False:
            raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
        else:
            resp_prev = requests.get(url + '/' + resp['block']['header']['parent'], params={'addr': addr}).json()
            if resp_prev['ok'] is False:
                raise ApiException(f"APIError with code {resp_prev['code']}: {resp_prev['msg']}")
            else:
                i = 0
                while i < len(list(resp_prev['block']['txs'].keys())):
                    if resp_prev['block']['txs'][list(resp_prev['block']['txs'].keys())[i]]['from'] == PublicAddress.txt2bin(
                            addr):

                        result[str(i)] = {'block': block}
                        result[str(i)]['addr'] = addr
                        result[str(i)]['to'] = PublicAddress.bin2txt(resp_prev['block']['txs'][list(resp_prev['block']['txs'].keys())[i]]['to'])
                        result[str(i)]['tr_am'] = resp_prev['block']['txs'][list(resp_prev['block']['txs'].keys())[i]]['payload'][0]['amount']
                        result[str(i)]['tr_cur'] = resp_prev['block']['txs'][list(resp_prev['block']['txs'].keys())[i]]['payload'][0]['cur']
                        if 'txext' in resp_prev['block']['txs'][list(resp_prev['block']['txs'].keys())[i]]:
                            result[str(i)]['msg'] = resp_prev['block']['txs'][list(resp_prev['block']['txs'].keys())[i]]['txext'][
                                'msg']
                    i += 1
            return result

    def get_prev_block_for_addr(self, addr, block='last'):
        settings = ClientII.get_endpoint_settings()
        result = '';
        if block == 'last':
        	url = settings['url'] + settings['address_info']
        	resp = requests.get(url + '/' + addr).json()
        	if resp['ok'] is False:
	            raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
        	else:
	            result = resp['info']['lastblk']
        	
        else:
            url = settings['url'] + settings['block_info']+ '/' + block
            #print(url)
            resp = requests.get(url).json()
            #print(resp)
            if resp['ok'] is False:
	            raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
            else:
                result = ''
                blockhain_addr=PublicAddress.txt2bin(addr)
                #print(PublicAddress.txt2bin(addr))
                #print('bals' in resp['block'])
                if blockhain_addr in resp['block']['bals']:
                    if 'lastblk' in resp['block']['bals'][blockhain_addr]:
	                    result = resp['block']['bals'][blockhain_addr]['lastblk']
        return result

    def get_tx_from_block(self, block, addr):
        settings = ClientII.get_endpoint_settings()
        url = settings['url'] + settings['block_info']
        time.sleep(2)
        #print(block)
        resp = requests.get(url + '/' + block, params={'addr': addr}).json()
        result = {}
        if resp['ok'] is False:
            raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
        else:
            i = 0
            #print(resp)
            #print(resp['block']['txs'].keys())
            while i < len(resp['block']['txs']):
                if resp['block']['txs'][list(resp['block']['txs'].keys())[i]]['from'] == PublicAddress.txt2bin(addr):

                    #result[str(i)] = {'block': block}
                    #result[str(i)]['addr'] = addr
                    #result[str(i)]['to'] = PublicAddress.bin2txt(resp['block']['txs'][list(resp['block']['txs'].keys())[i]]['to'])
                    #result[str(i)]['tr_am'] = resp['block']['txs'][list(resp['block']['txs'].keys())[i]]['payload'][0]['amount']
                    #result[str(i)]['tr_cur'] = resp['block']['txs'][list(resp['block']['txs'].keys())[i]]['payload'][0]['cur']
                    #result[str(i)]['seq'] = PublicAddress.bin2txt(resp['block']['txs'][list(resp['block']['txs'].keys())[i]]['seq'])
                    #result[str(i)]['time'] = PublicAddress.bin2txt(resp['block']['txs'][list(resp['block']['txs'].keys())[i]]['t'])
                    #if 'txext' in resp['block']['txs'][list(resp['block']['txs'].keys())[i]]:
                        #result[str(i)]['txext'] = resp['block']['txs'][list(resp['block']['txs'].keys())[i]]['txext']
                    result[str(i)]=resp['block']['txs'][list(resp['block']['txs'].keys())[i]]
                    #print(resp['block']['txs'][list(resp['block']['txs'].keys())[i]])
                i += 1
        return result
		
			
    def transaction(self, private_key, times, nonce, msg, fr, to, p):
        public_key = private_key.public().compressed
        settings = ClientII.get_endpoint_settings()
        fr_bin = binascii.unhexlify(PublicAddress.txt2bin(fr))
        to_bin = binascii.unhexlify(PublicAddress.txt2bin(to))		
        tx = base64.b64encode(self.pack_tx(self.transfer_tx_body(fr_bin, to_bin, p, times, nonce, msg), self.generate_sign_data(private_key, public_key, times, self.transfer_tx_body(fr_bin, to_bin, p, times, nonce, msg))))
        data = {"tx": str(tx)[2:-1]}
        url = settings['url'] + settings['new_tx']
        resp = requests.post(url, json=data).json()

        if resp['ok'] is False:
            raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
        else:

            time.sleep(5)
            status_url = settings['url'] + settings['tx_status']
            status_resp = requests.get(status_url + '/' + resp['txid']).json()
            if status_resp['ok'] is False:
                raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
            else:
                i = 0
                while (status_resp['res'] is None) and (i < 10):
                    i += 1
                    print('Try get transaction info. #' + str(i) + "   " + status_url + '/' + resp['txid'])
                    time.sleep(2)
                    status_resp = requests.get(status_url + '/' + resp['txid']).json()

                if status_resp['ok'] is False:
                    raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
                else:
                    if status_resp['res'] is None:
                        return {
                                    "error: ": True,
                                    "error_msg: ": "Can't get transaction info after 10 attempt",
                            }
                    else:
                        if 'error' in status_resp['res']:
                            if status_resp['res']['error'] is True:
                                return {
                                    "error: ": True,
                                    "error_msg: ": status_resp['res']['res'],
                                }
                        else:
                            addr_url = settings['url'] + settings['address_info']
                            addr_info = requests.get(addr_url + '/0x' + PublicAddress.txt2bin(fr)).json()
                            if addr_info['ok'] is False:
                                raise ApiException(f"APIError with code {resp['code']}: {resp['msg']}")
                            else:
                                return status_resp
