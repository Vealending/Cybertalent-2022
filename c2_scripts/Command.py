#!/usr/bin/env python3

# Modified for easy export of the Command object

import base64
import javaobj

from Crypto.Signature import DSS
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256

from datetime import datetime


class Command(object):
    pubkey: bytes = b"MIIDQjCCAjUGByqGSM44BAEwggIoAoIBAQCPeTXZuarpv6vtiHrPSVG28y7FnjuvNxjo6sSWHz79NgbnQ1GpxBgzObgJ58KuHFObp0dbhdARrbi0eYd1SYRpXKwOjxSzNggooi/6JxEKPWKpk0U0CaD+aWxGWPhL3SCBnDcJoBBXsZWtzQAjPbpUhLYpH51kjviDRIZ3l5zsBLQ0pqwudemYXeI9sCkvwRGMn/qdgYHnM423krcw17njSVkvaAmYchU5Feo9a4tGU8YzRY+AOzKkwuDycpAlbk4/ijsIOKHEUOThjBopo33fXqFD3ktm/wSQPtXPFiPhWNSHxgjpfyEc2B3KI8tuOAdl+CLjQr5ITAV2OTlgHNZnAh0AuvaWpoV499/e5/pnyXfHhe8ysjO65YDAvNVpXQKCAQAWplxYIEhQcE51AqOXVwQNNNo6NHjBVNTkpcAtJC7gT5bmHkvQkEq9rI837rHgnzGC0jyQQ8tkL4gAQWDt+coJsyB2p5wypifyRz6Rh5uixOdEvSCBVEy1W4AsNo0fqD7UielOD6BojjJCilx4xHjGjQUntxyaOrsLC+EsRGiWOefTznTbEBplqiuH9kxoJts+xy9LVZmDS7TtsC98kOmkltOlXVNb6/xF1PYZ9j897buHOSXC8iTgdzEpbaiH7B5HSPh++1/et1SEMWsiMt7lU92vAhErDR8C2jCXMiT+J67ai51LKSLZuovjntnhA6Y8UoELxoi34u1DFuHvF9veA4IBBQACggEADkENe3FyODSBndQfXkLHhXJWJr43CgzKOm3IauPLMOcKLipK3Ta8fzVLMZnnlqzcdiwhqI4wKtUz5K5ZXzuQ6BKAGPPgwYyzAJ32eYiC6GXtvOquBS38WSgz7k5WbJ+gvVAHiWnFtvlLZT0l2rtn2m2AyJaVbCiZxt18qzIPfLV5lNF8y/MOyBiWTJ0ooPwspQchURyl8JbMdHmoYovSscHNygYTPUleg7we00Q2hPiEKYMHrj+UBYzMhrmCSGoNHBV27IjK+KGEKEb1l8JZbu/4hI4S1YeJGLcZ9mROSrb4+BNpHzteZAF+MNDKPvTgVeDjNGAnIi4j+yhp0HqmHA=="

    def __init__(self, fd) -> None:
        obj: javaobj.JavaObject = javaobj.load(fd)
        self.type: str = "class " + obj.get_class().name
        self.recipient: str = obj.recipient
        self.run_after: int = obj.runAfter.second + obj.runAfter.nano / 1e9
        self.value: str = obj.value
        self.signature: bytes = bytes(
            map(lambda x: (x + 256) % 256, obj.signature._data)
        )

    def verify(self):
        pub = DSA.import_key(base64.b64decode(self.pubkey))
        hash = SHA256.new(self.__str__().encode())
        sig: DSS.FipsDsaSigScheme = DSS.new(pub, mode="fips-186-3", encoding="der")
        return sig.verify(hash, self.signature)

    def __str__(self) -> str:
        when = datetime.utcfromtimestamp(self.run_after)
        return (
            f"- Recipient: {self.recipient}\n"
            + f"- When: {when:%Y-%m-%dT%H:%M:%SZ}\n"
            + f"- Type: {self.type}\n"
            + f"- Value: {self.value}\n"
        )