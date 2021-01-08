import jwcrypto.jwk as jwk
import python_jwt as jwt
import datetime


def writefile(filename, key):
    file = open(filename, "wb")
    file.write(key)
    file.close()


def readfile(filename):
    file = open(filename, 'rb')
    text = file.read()
    file.close()
    return text


def generateRSA():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    public_key = key.export_to_pem()
    writefile("public.key", public_key)

    privatepassword = 'password1234567890'
    private_key = key.export_to_pem(private_key=True, password=None)
    # private_key = key.export_to_pem(private_key=True, password=bytes(privatepassword, 'UTF-8'))
    writefile("private.key", private_key)


def openPrivatekey():
    private_key = jwk.JWK.from_pem(readfile('private.key'))
    private_key = private_key.export()
    return private_key


def openPublickey():
    public_key = jwk.JWK.from_pem(readfile('public.key'))
    public_key = public_key.export()
    return public_key


def signRSA(private_key, payload):
    # token = jwt.generate_jwt(payload, jwk.JWK.from_json(private_key), 'RS256')
    token = jwt.generate_jwt(payload, jwk.JWK.from_json(private_key), 'RS256', datetime.timedelta(minutes=60))
    return token


def verifyRSA(public_key, token):
    header, claims = jwt.verify_jwt(token, jwk.JWK.from_json(public_key), ['RS256'])
    return header, claims


if __name__ == '__main__':
    # generateRSA()

    private_key = openPrivatekey()
    public_key = openPublickey()
    print(private_key)
    print(public_key)

    # 데이터
    payload = {'iss': 'daeseong.com', 'exp': 1485270000000, "https://daeseong.com/jwt": 'true',
               "userId": "userId1234567890", "username": "daeseong"}
    token = signRSA(private_key, payload)
    print(token)

    header, claims = verifyRSA(public_key, token)
    print(header)
    print(claims)

    pass
