import hashlib
import binascii
import base58
from requests import get
import bitcoin

# got from console while analyzing the html/js page
mod = 3000
# multiply = [213623032, 226227782, 99391191, 31904303, 81706]
# add = [9520393, 76419088, 233137143, 1583]
multiply = 424242424242424244242424244242424242424
add = 30636472460825297682340857097

keys = [{} for _ in range(0, mod)]
adds = [{} for _ in range(0, mod)]

for i in range(0, mod):
    # source:   https://gist.github.com/imylomylo/60e47d1902c350179a47eb3c1ffe8c5d
    #           https://www.youtube.com/watch?v=2idX-V8riy0
    key = i*multiply + add
    hex_key = hex(key).replace("0x", "")
    padded_key_str = str(hex_key).zfill(64)
    extended_key = "80" + padded_key_str + "01"

    first_hash = hashlib.sha256(binascii.unhexlify(extended_key)).digest()
    second_hash = hashlib.sha256(first_hash).hexdigest()
    final_key = extended_key + second_hash[:8]
    WIF = base58.b58encode(binascii.unhexlify(final_key)).decode()
    keys[i] = WIF
    adds[i] = bitcoin.privtoaddr(WIF)

index = 0
for add in adds:
    print("Processing index: {}".format(index))

    # source:   https://bitcoin.stackexchange.com/questions/30474/can-i-use-blockchain-api-to-get-number-of-transactions-at-btc-address
    request = get("https://blockchain.info/address/{}?format=json".format(add))
    if request.status_code != 200:
        print("Failed.")
        break
    elif request.json()['n_tx'] > 0:
        print("Success at address: {}, with private-key: {}.".format(add, keys[index]))
        break;

    index += 1
