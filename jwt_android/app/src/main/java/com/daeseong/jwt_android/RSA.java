package com.daeseong.jwt_android;

import android.os.Build;
import android.util.Log;

import androidx.annotation.RequiresApi;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RequiresApi(api = Build.VERSION_CODES.O)
public class RSA {

    private static final String TAG = RSA.class.getSimpleName();

    private String sPWD = "password1234567890";

    private Base64.Encoder encoder = Base64.getEncoder();
    private Base64.Decoder decoder = Base64.getDecoder();

    public String createToken(String iss, Long exp, Boolean http, String userId, String userName) {

        String token = "";

        try {
            Map<String, Object> header = new HashMap<String, Object>();
            header.put("alg", "RS256");
            header.put("typ", "JWT");

            RSAPrivateKey PrivKey = rsaPrivateKey();
            //RSAPublicKey publicKey = rsaPublicKey();

            token = JWT.create()
                    .withHeader(header)
                    .withClaim("iss", iss)
                    .withClaim("exp", exp)
                    .withClaim("https://daeseong.com/jwt", http)
                    .withClaim("userId", userId)
                    .withClaim("userName", userName)
                    .sign(Algorithm.RSA256((RSAPrivateKey) PrivKey));

        }catch (Exception ex){
            ex.getMessage().toString();
        }
        return token;
    }

    public Boolean verifyToken(String token) throws InvalidKeySpecException, NoSuchAlgorithmException {

        try {

            RSAPublicKey publicKey = rsaPublicKey();
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm).build();

            DecodedJWT jwt = verifier.verify(token);

            String iss = jwt.getClaim("iss").asString();
            Long exp = jwt.getClaim("exp").asLong();
            Boolean bsite = jwt.getClaim("https://daeseong.com/jwt").asBoolean();
            String userId = jwt.getClaim("userId").asString();
            String userName = jwt.getClaim("userName").asString();
            Log.e(TAG, "iss:" + iss);
            Log.e(TAG, "exp:" + exp);
            Log.e(TAG, "https://daeseong.com/jwt:" + bsite);
            Log.e(TAG, "userId:" + userId);
            Log.e(TAG, "userName:" + userName);

        } catch (JWTVerificationException exception) {
            return false;
        }
        return true;
    }

    public String getHeader(String sToken) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String Header = "";
        try {
            RSAPublicKey publicKey = rsaPublicKey();
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(sToken);
            Header = new String(android.util.Base64.decode(jwt.getHeader(), android.util.Base64.URL_SAFE));
        } catch (JWTVerificationException exception) {
            exception.getMessage().toString();
        }
        return Header;
    }

    public String getPayload(String sToken) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String payload = "";
        try {
            RSAPublicKey publicKey = rsaPublicKey();
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(sToken);
            payload = new String(android.util.Base64.decode(jwt.getPayload(), android.util.Base64.URL_SAFE));
        } catch (JWTVerificationException exception) {
            exception.getMessage().toString();
        }
        return payload;
    }

    private RSAPublicKey rsaPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {

        String keyString = //"-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4aEhJrZBMErXtGpxSwxv" +
                "3TN4tTAklbcySUyIHH7jgge+aZnv1jpw7w2ZAZHaEnJYKUj7g3R9hD1W+DSqQ7CA" +
                "wYbvKzLfEakfkzCE2JrMTDviAKP6ZgxQO0kNVUDYgEISQKkweuu5aX6nJ17x27pG" +
                "D62VpzRJ95dVlHXAkmMCaiJQGXxzWZ7wU6R6xvGNW47+uZJFSyK8z4YJeqYi84Dr" +
                "5i+W03F1mdirYwqEWXyoQm7+DlQlplBXzPmZPaHtww/Bl1CjiFEF9iw+JcKdIF4+" +
                "/lFFZ1pCmqDM1B0QNOtJDTDuYo0uOVybkeohxFwnIBeteqF5vPFmy7wZWqAHSdO4" +
                "ZQIDAQAB";
                //"-----END PUBLIC KEY-----";

        X509EncodedKeySpec ks = new X509EncodedKeySpec(decoder.decode(keyString));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(ks);
    }

    private RSAPrivateKey rsaPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {

        String keyString = //"-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDhoSEmtkEwSte0" +
                "anFLDG/dM3i1MCSVtzJJTIgcfuOCB75pme/WOnDvDZkBkdoSclgpSPuDdH2EPVb4" +
                "NKpDsIDBhu8rMt8RqR+TMITYmsxMO+IAo/pmDFA7SQ1VQNiAQhJAqTB667lpfqcn" +
                "XvHbukYPrZWnNEn3l1WUdcCSYwJqIlAZfHNZnvBTpHrG8Y1bjv65kkVLIrzPhgl6" +
                "piLzgOvmL5bTcXWZ2KtjCoRZfKhCbv4OVCWmUFfM+Zk9oe3DD8GXUKOIUQX2LD4l" +
                "wp0gXj7+UUVnWkKaoMzUHRA060kNMO5ijS45XJuR6iHEXCcgF616oXm88WbLvBla" +
                "oAdJ07hlAgMBAAECggEBAIWsO4K+2XIt9QuLQGGxFZkchHf79MDKTz2D3OPc/Rat" +
                "Vc8khyYJa50FFlAKxALHwZl8Bp6D5lTxLlRQh0shB7cgJRQXyHajFvTR+vKFC2Ji" +
                "2+t7Or84rlPhXMfUai/adQvf8Lvyad+pTIiTxIBkJFvngFEWNng8LVSOSq+vft+3" +
                "Jaqf/HEfz9hw8MDXYDW94JS+fhRVbgbBBEUBjK0F45WSO0e6cNcuCmDm7kr73v6W" +
                "ZORVda/sHPVaD5VPze5mhk/qNs4H2q3+qqsIULp+Ffx4MEi8xj+qp24PQfGrv/k+" +
                "Pg3YPpCRpe6YD/zhKuCPjXtwoTj6FQpSFoM27oKPYSECgYEA8kmUNPlygT7e0zDR" +
                "SqeNYN8dvxQ7mp03yI/gUlRDo8RYTWNNXnwl1OovVYnVmiBQp+CpYSPNvqWWm6Y1" +
                "/6LmKuliVVVHchi2nhCMSY7fK93U2Kas4ISuA5xoG0LM6fNgqbSdR5L9cwb488oO" +
                "xIwYBlOexcRcXkRz6ClsE8oCLWkCgYEA7mYyxJHEXwtgwwyWf68sPZEJqRFsQ53y" +
                "zAy/20yqyWX8BPdkZ5jRJnuXI2D7atHPFocpsjDiw1d1a1/5vrR1AwZpAMJEWkXt" +
                "xzW0UFGv6kOlsAgb94cXReFFJZJ77vfAOYXeCyHS/l69hgGFXu1csQC99NUYQQmS" +
                "hSSxQnVAB50CgYBSw4WoDunpcoOFWvCzcsbdp3mu0weFSl1K2rMDDJvKboDHdrtw" +
                "IjJ+J70hmCLqMk26+wiBEUzv6fqnksBxYcEEOZMImUf9lqmTFw4E9pQPlQhnNZBq" +
                "ZYhX3W7GmSwMYsHLVtI/J9wCFgimpogi5cQzLQ9YeTogTXvWe4favq+9uQKBgASV" +
                "WmyFEO1y3o1hdJNH3uXgH/tsJlS2eLCLnjStKKtuloXR69BCE+NVhPZdKvhGyGB6" +
                "gMa4QePXjp5d3gNYnNdODD7DfWTu6z9lPO4+Y89xNYJI5aDArCXfyuCKDG/vu3Zf" +
                "qIE2SUQythoZdWL51Uph5UULw8ecU4DTz8SjVHPRAoGBAKxI4ngJwybnLVgK7eKs" +
                "DDptIfIuvstZi2Ji+S/dEJPGqAJrfpNmkVIumDJcgQzRo3sFH0NwG0HftPQh43xA" +
                "zbT8ck23rwZmLxsgC+Xw22j8WNmBFDSmkW6ymkdu1zqneV1IVfkPhHtw/i2Sa77P" +
                "Q6M3HKUQantoFFRXXECVH4Up";
                //"-----END PRIVATE KEY-----\n";

        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(decoder.decode(keyString));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(ks);
    }
}
