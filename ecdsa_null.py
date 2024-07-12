from ecdsa.ecdsa import Signature
from ecdsa.util import sigencode_der
import base64

sig = Signature(0,0)

print(base64.urlsafe_b64encode(sigencode_der(0,0,1)))