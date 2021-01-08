from HS256def.defHS256 import encodeHA256, decodeHA256, jwt_header
from RSAdef.defjwt import generateRSA, signRSA, verifyRSA, openPrivatekey, openPublickey


def HS256_test():
    key = "password1234567890"
    payload = {'iss': 'daeseong.com', 'exp': 1485270000000, "https://daeseong.com/jwt": 'true',
               "userId": "userId1234567890", "username": "daeseong"}
    encoded = encodeHA256(key, payload)
    print("encoded:" + encoded)

    head = jwt_header(encoded)
    print("head:" + str(head))

    decoded = decodeHA256(key, encoded)
    print("decoded:" + str(decoded))


def RSA_test():
    # generateRSA()

    private_key = openPrivatekey()
    public_key = openPublickey()

    payload = {'iss': 'daeseong.com', 'exp': 1485270000000, "https://daeseong.com/jwt": 'true',
               "userId": "userId1234567890", "username": "daeseong"}
    token = signRSA(private_key, payload)
    print("token:" + token)

    header, claims = verifyRSA(public_key, token)
    print("header:" + str(header))
    print("claims:" + str(claims))


if __name__ == '__main__':
    HS256_test()
    RSA_test()
