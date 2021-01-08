import jwt


def encodeHA256(key, input):
    encoded = jwt.encode(input, key, algorithm="HS256")
    return encoded


def jwt_header(input):
    hed = jwt.get_unverified_header(input)
    return hed


def decodeHA256(key, input):
    decoded = jwt.decode(input, key, algorithms="HS256")
    return decoded


if __name__ == '__main__':
    """
        헤더(Header)
        typ: 토큰타입 JWT
        alg: 해싱 알고리즘 HMAC-SHA256, RSA

        정보(Payload)
        iss: 토큰 발급자(issuer)
        sub: 토큰 제목(subject)
        aud: 토큰 대상자(audience)
        exp: 토큰의 만료시간, 시간은 NumericDate
        iat: 토큰이 발급된 시간(issuedat) 이 값을 이용하여 토큰의 age를 판단
        jti: JWT의 고유 식별자 중복 방지
        nbf: Not Before 를 의미, NumericDate 날짜 지정
        """

    key = "password1234567890"
    payload = {'iss': 'daeseong.com', 'exp': 1485270000000, "https://daeseong.com/jwt": 'true',
               "userId": "userId1234567890", "username": "daeseong"}
    encoded = encodeHA256(key, payload)
    print(encoded)

    head = jwt_header(encoded)
    print(head)

    decoded = decodeHA256(key, encoded)
    print(decoded)

    pass
