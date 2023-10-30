import ecdsa
from ecdsa.curves import SECP256k1
from ecdsa.keys import SigningKey
from Crypto.Hash import keccak,SHA256
from base58 import b58encode as b58
import random
import secrets
import time
import base58


def save(pk,wl,file="tron-wallets.txt"):
	with open(file,'a') as f:
		f.write(f"{wl} {pk}\n")

def generateBytes(length=64):
	if length % 2 != 0:
		raise ValueError("Length must be an even number")
	random_bytes = secrets.token_bytes(length // 2)
	private_key_hex = random_bytes.hex()
	return private_key_hex

def kecc256(data):
	res = keccak.new(digest_bits=256)
	res.update(bytes.fromhex(data))
	return res.hexdigest()

def sha256(data):
	res = SHA256.new()
	res.update(bytes.fromhex(data))
	return res.hexdigest()

def wallet(privKey_hex: str):
	privKey = SigningKey.from_string(bytes.fromhex(privKey_hex), curve=SECP256k1)
	pubKey = privKey.get_verifying_key().to_string(encoding="uncompressed").hex()
	pub = pubKey[2:]
	ketja = kecc256(pub)
	kec = ketja[24:]
	stepsis = '41'+kec
	sh1 = sha256(stepsis)
	sh2 = sha256(sh1)
	cksum = sh2[0:8]
	lolita = stepsis+cksum
	result = b58(bytes.fromhex(lolita)).decode()
	return result

def plaintoAddress(data):
	decoded_bytes = base58.b58decode(data)
	hex_str = decoded_bytes.hex()
	return hex_str[0:-8]

def create(jumlah:int,submain=None):
	st = time.time()
	for _ in range(jumlah):
		pk=generateBytes()
		if submain is not None:
			pk = kecc256(submain+pk)
		wl=wallet(pk)
		save(pk,wl)
	fn = time.time()
	print(f"Complete in: {fn-st:.2f}")


if __name__ == '__main__':
	try:
	   create(int(input(' [ ? ] Jumlah Wallet TRX > ')))
	except:
		exit('Error...')
