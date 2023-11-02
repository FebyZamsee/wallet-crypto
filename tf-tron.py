from pprint import pprint
import hashlib
import requests
import base58
import ecdsa
from Crypto.Hash import keccak
import requests as r
import random

url = 'https://api.trongrid.io'
def keccak256(data):
	hasher = keccak.new(digest_bits=256)
	hasher.update(data)
	return hasher.digest()


def verifying_key_sendto(key):
	pubKey = key.to_string()
	primitive_addr = b'\x41' + keccak256(pubKey)[-20:]
	addr = base58.b58encode_check(primitive_addr)
	return addr

def proci():
	with open("proxy.txt") as file:
		proxies = file.read().strip().splitlines()
	return random.choice(proxies)

def ceksaldo(wallet):
	pro = proci()
	prox = {
		"http":pro,
		"https":pro
	}
	result = r.get(f"https://apilist.tronscanapi.com/api/accountv2?address={wallet}",proxies=prox)
	saldo = result.json()["withPriceTokens"][0]["amount"]
	# saldo = float(saldo)
	return saldo


def main(file="wallet.txt"):
	sendTotal = 0
	for  wlPK in open(file,'r').read().strip().splitlines():
		resText = ''
		privKey = wlPK.split(' ')[1]
		raw_priv_key = bytes.fromhex(privKey)
		priv_key = ecdsa.SigningKey.from_string(raw_priv_key, curve=ecdsa.SECP256k1)
		pubKey = priv_key.get_verifying_key().to_string()
		primitive_addr = b'\x41' + keccak256(pubKey)[-20:]
		addr = base58.b58encode_check(primitive_addr)
		resText += f" [{addr.decode()}]"
		saldo = ceksaldo(addr.decode())
		resText += f" {float(saldo):.3f} TRX"
		if float(saldo) > 0:
			jumlah = int(float(saldo) * 1000000)
			resText += ' | '+'SENDING'
			transaction = {
				"to_address": base58.b58decode_check(sendto).hex(),
				"owner_address": primitive_addr.hex(),
				"amount": jumlah,
			}
			resp = requests.post(url + '/wallet/createtransaction', json=transaction)
			payload = resp.json()
			if 'message' in payload:
				resText += ' | '+str(bytes.fromhex(payload['message']).decode())
			raw_data = bytes.fromhex(payload['raw_data_hex'])
			signature = priv_key.sign_deterministic(raw_data, hashfunc=hashlib.sha256)
			pubKeys = ecdsa.VerifyingKey.from_public_key_recovery(
				signature[:64], raw_data, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256
			)
			for v, pk in enumerate(pubKeys):
				if verifying_key_sendto(pk) == addr:
					break
			signature += bytes([v])
			payload['signature'] = [signature.hex()]
			resp = requests.post(url + '/wallet/broadcasttransaction', json=payload)
			result = resp.json()
			if 'message' in result:
				resText += ' | '+str(bytes.fromhex(result['message']).decode())
			else:
				resText += ' | '+str(result)
			sendTotal += jumlah
		print(resText)
	print(f"Total : {sendTotal/1000000} TRX")
if __name__ == '__main__':
	sendto = input(' [ ? ] Send to Wallet > ')
	filename = input(' [ ? ] Saved File Name > ')
	main(filename)
